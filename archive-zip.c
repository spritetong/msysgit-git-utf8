/*
 * Copyright (c) 2006 Rene Scharfe
 */
#include "cache.h"
#include "archive.h"
#include "streaming.h"

static int zip_date;
static int zip_time;

static unsigned char *zip_dir;
static unsigned int zip_dir_size;

static unsigned int zip_offset;
static unsigned int zip_dir_offset;
static unsigned int zip_dir_entries;

#define ZIP_DIRECTORY_MIN_SIZE	(1024 * 1024)
#define ZIP_STREAM (8)

struct zip_local_header {
	unsigned char magic[4];
	unsigned char version[2];
	unsigned char flags[2];
	unsigned char compression_method[2];
	unsigned char mtime[2];
	unsigned char mdate[2];
	unsigned char crc32[4];
	unsigned char compressed_size[4];
	unsigned char size[4];
	unsigned char filename_length[2];
	unsigned char extra_length[2];
	unsigned char _end[1];
};

struct zip_data_desc {
	unsigned char magic[4];
	unsigned char crc32[4];
	unsigned char compressed_size[4];
	unsigned char size[4];
	unsigned char _end[1];
};

struct zip_dir_header {
	unsigned char magic[4];
	unsigned char creator_version[2];
	unsigned char version[2];
	unsigned char flags[2];
	unsigned char compression_method[2];
	unsigned char mtime[2];
	unsigned char mdate[2];
	unsigned char crc32[4];
	unsigned char compressed_size[4];
	unsigned char size[4];
	unsigned char filename_length[2];
	unsigned char extra_length[2];
	unsigned char comment_length[2];
	unsigned char disk[2];
	unsigned char attr1[2];
	unsigned char attr2[4];
	unsigned char offset[4];
	unsigned char _end[1];
};

struct zip_dir_trailer {
	unsigned char magic[4];
	unsigned char disk[2];
	unsigned char directory_start_disk[2];
	unsigned char entries_on_this_disk[2];
	unsigned char entries[2];
	unsigned char size[4];
	unsigned char offset[4];
	unsigned char comment_length[2];
	unsigned char _end[1];
};

/*
 * On ARM, padding is added at the end of the struct, so a simple
 * sizeof(struct ...) reports two bytes more than the payload size
 * we're interested in.
 */
#define ZIP_LOCAL_HEADER_SIZE	offsetof(struct zip_local_header, _end)
#define ZIP_DATA_DESC_SIZE	offsetof(struct zip_data_desc, _end)
#define ZIP_DIR_HEADER_SIZE	offsetof(struct zip_dir_header, _end)
#define ZIP_DIR_TRAILER_SIZE	offsetof(struct zip_dir_trailer, _end)

static void copy_le16(unsigned char *dest, unsigned int n)
{
	dest[0] = 0xff & n;
	dest[1] = 0xff & (n >> 010);
}

static void copy_le32(unsigned char *dest, unsigned int n)
{
	dest[0] = 0xff & n;
	dest[1] = 0xff & (n >> 010);
	dest[2] = 0xff & (n >> 020);
	dest[3] = 0xff & (n >> 030);
}

static void *zlib_deflate(void *data, unsigned long size,
		int compression_level, unsigned long *compressed_size)
{
	git_zstream stream;
	unsigned long maxsize;
	void *buffer;
	int result;

	memset(&stream, 0, sizeof(stream));
	git_deflate_init(&stream, compression_level);
	maxsize = git_deflate_bound(&stream, size);
	buffer = xmalloc(maxsize);

	stream.next_in = data;
	stream.avail_in = size;
	stream.next_out = buffer;
	stream.avail_out = maxsize;

	do {
		result = git_deflate(&stream, Z_FINISH);
	} while (result == Z_OK);

	if (result != Z_STREAM_END) {
		free(buffer);
		return NULL;
	}

	git_deflate_end(&stream);
	*compressed_size = stream.total_out;

	return buffer;
}

static void write_zip_data_desc(unsigned long size,
				unsigned long compressed_size,
				unsigned long crc)
{
	struct zip_data_desc trailer;

	copy_le32(trailer.magic, 0x08074b50);
	copy_le32(trailer.crc32, crc);
	copy_le32(trailer.compressed_size, compressed_size);
	copy_le32(trailer.size, size);
	write_or_die(1, &trailer, ZIP_DATA_DESC_SIZE);
}

static void set_zip_dir_data_desc(struct zip_dir_header *header,
				  unsigned long size,
				  unsigned long compressed_size,
				  unsigned long crc)
{
	copy_le32(header->crc32, crc);
	copy_le32(header->compressed_size, compressed_size);
	copy_le32(header->size, size);
}

static void set_zip_header_data_desc(struct zip_local_header *header,
				     unsigned long size,
				     unsigned long compressed_size,
				     unsigned long crc)
{
	copy_le32(header->crc32, crc);
	copy_le32(header->compressed_size, compressed_size);
	copy_le32(header->size, size);
}

#define STREAM_BUFFER_SIZE (1024 * 16)

static int write_zip_entry(struct archiver_args *args,
			   const unsigned char *sha1,
			   const char *path, size_t pathlen,
			   unsigned int mode)
{
	struct zip_local_header header;
	struct zip_dir_header dirent;
	unsigned long attr2;
	unsigned long compressed_size;
	unsigned long crc;
	unsigned long direntsize;
	int method;
	unsigned char *out;
	void *deflated = NULL;
	void *buffer;
	struct git_istream *stream = NULL;
	unsigned long flags = 0;
	unsigned long size;

	/* For UTF-8. Changed by Sprite Tong, 12/7/2011. */
	flags |= (1 << 11);

	crc = crc32(0, NULL, 0);

	if (pathlen > 0xffff) {
		return error("path too long (%d chars, SHA1: %s): %s",
				(int)pathlen, sha1_to_hex(sha1), path);
	}

	if (S_ISDIR(mode) || S_ISGITLINK(mode)) {
		method = 0;
		attr2 = 16;
		out = NULL;
		size = 0;
		compressed_size = 0;
		buffer = NULL;
		size = 0;
	} else if (S_ISREG(mode) || S_ISLNK(mode)) {
		enum object_type type = sha1_object_info(sha1, &size);

		method = 0;
		attr2 = S_ISLNK(mode) ? ((mode | 0777) << 16) :
			(mode & 0111) ? ((mode) << 16) : 0;
		if (S_ISREG(mode) && args->compression_level != 0 && size > 0)
			method = 8;
		compressed_size = size;

		if (S_ISREG(mode) && type == OBJ_BLOB && !args->convert &&
		    size > big_file_threshold) {
			stream = open_istream(sha1, &type, &size, NULL);
			if (!stream)
				return error("cannot stream blob %s",
					     sha1_to_hex(sha1));
			flags |= ZIP_STREAM;
			out = buffer = NULL;
		} else {
			buffer = sha1_file_to_archive(args, path, sha1, mode,
						      &type, &size);
			if (!buffer)
				return error("cannot read %s",
					     sha1_to_hex(sha1));
			crc = crc32(crc, buffer, size);
			out = buffer;
		}
	} else {
		return error("unsupported file mode: 0%o (SHA1: %s)", mode,
				sha1_to_hex(sha1));
	}

	if (buffer && method == 8) {
		deflated = zlib_deflate(buffer, size, args->compression_level,
				&compressed_size);
		if (deflated && compressed_size - 6 < size) {
			/* ZLIB --> raw compressed data (see RFC 1950) */
			/* CMF and FLG ... */
			out = (unsigned char *)deflated + 2;
			compressed_size -= 6;	/* ... and ADLER32 */
		} else {
			method = 0;
			compressed_size = size;
		}
	}

	/* make sure we have enough free space in the dictionary */
	direntsize = ZIP_DIR_HEADER_SIZE + pathlen;
	while (zip_dir_size < zip_dir_offset + direntsize) {
		zip_dir_size += ZIP_DIRECTORY_MIN_SIZE;
		zip_dir = xrealloc(zip_dir, zip_dir_size);
	}

	copy_le32(dirent.magic, 0x02014b50);
	copy_le16(dirent.creator_version,
		S_ISLNK(mode) || (S_ISREG(mode) && (mode & 0111)) ? 0x0317 : 0);
	copy_le16(dirent.version, 10);
	copy_le16(dirent.flags, flags);
	copy_le16(dirent.compression_method, method);
	copy_le16(dirent.mtime, zip_time);
	copy_le16(dirent.mdate, zip_date);
	set_zip_dir_data_desc(&dirent, size, compressed_size, crc);
	copy_le16(dirent.filename_length, pathlen);
	copy_le16(dirent.extra_length, 0);
	copy_le16(dirent.comment_length, 0);
	copy_le16(dirent.disk, 0);
	copy_le16(dirent.attr1, 0);
	copy_le32(dirent.attr2, attr2);
	copy_le32(dirent.offset, zip_offset);

	copy_le32(header.magic, 0x04034b50);
	copy_le16(header.version, 10);
	copy_le16(header.flags, flags);
	copy_le16(header.compression_method, method);
	copy_le16(header.mtime, zip_time);
	copy_le16(header.mdate, zip_date);
	if (flags & ZIP_STREAM)
		set_zip_header_data_desc(&header, 0, 0, 0);
	else
		set_zip_header_data_desc(&header, size, compressed_size, crc);
	copy_le16(header.filename_length, pathlen);
	copy_le16(header.extra_length, 0);
	write_or_die(1, &header, ZIP_LOCAL_HEADER_SIZE);
	zip_offset += ZIP_LOCAL_HEADER_SIZE;
	write_or_die(1, path, pathlen);
	zip_offset += pathlen;
	if (stream && method == 0) {
		unsigned char buf[STREAM_BUFFER_SIZE];
		ssize_t readlen;

		for (;;) {
			readlen = read_istream(stream, buf, sizeof(buf));
			if (readlen <= 0)
				break;
			crc = crc32(crc, buf, readlen);
			write_or_die(1, buf, readlen);
		}
		close_istream(stream);
		if (readlen)
			return readlen;

		compressed_size = size;
		zip_offset += compressed_size;

		write_zip_data_desc(size, compressed_size, crc);
		zip_offset += ZIP_DATA_DESC_SIZE;

		set_zip_dir_data_desc(&dirent, size, compressed_size, crc);
	} else if (stream && method == 8) {
		unsigned char buf[STREAM_BUFFER_SIZE];
		ssize_t readlen;
		git_zstream zstream;
		int result;
		size_t out_len;
		unsigned char compressed[STREAM_BUFFER_SIZE * 2];

		memset(&zstream, 0, sizeof(zstream));
		git_deflate_init(&zstream, args->compression_level);

		compressed_size = 0;
		zstream.next_out = compressed;
		zstream.avail_out = sizeof(compressed);

		for (;;) {
			readlen = read_istream(stream, buf, sizeof(buf));
			if (readlen <= 0)
				break;
			crc = crc32(crc, buf, readlen);

			zstream.next_in = buf;
			zstream.avail_in = readlen;
			result = git_deflate(&zstream, 0);
			if (result != Z_OK)
				die("deflate error (%d)", result);
			out = compressed;
			if (!compressed_size)
				out += 2;
			out_len = zstream.next_out - out;

			if (out_len > 0) {
				write_or_die(1, out, out_len);
				compressed_size += out_len;
				zstream.next_out = compressed;
				zstream.avail_out = sizeof(compressed);
			}

		}
		close_istream(stream);
		if (readlen)
			return readlen;

		zstream.next_in = buf;
		zstream.avail_in = 0;
		result = git_deflate(&zstream, Z_FINISH);
		if (result != Z_STREAM_END)
			die("deflate error (%d)", result);

		git_deflate_end(&zstream);
		out = compressed;
		if (!compressed_size)
			out += 2;
		out_len = zstream.next_out - out - 4;
		write_or_die(1, out, out_len);
		compressed_size += out_len;
		zip_offset += compressed_size;

		write_zip_data_desc(size, compressed_size, crc);
		zip_offset += ZIP_DATA_DESC_SIZE;

		set_zip_dir_data_desc(&dirent, size, compressed_size, crc);
	} else if (compressed_size > 0) {
		write_or_die(1, out, compressed_size);
		zip_offset += compressed_size;
	}

	free(deflated);
	free(buffer);

	memcpy(zip_dir + zip_dir_offset, &dirent, ZIP_DIR_HEADER_SIZE);
	zip_dir_offset += ZIP_DIR_HEADER_SIZE;
	memcpy(zip_dir + zip_dir_offset, path, pathlen);
	zip_dir_offset += pathlen;
	zip_dir_entries++;

	return 0;
}

static void write_zip_trailer(const unsigned char *sha1)
{
	struct zip_dir_trailer trailer;

	copy_le32(trailer.magic, 0x06054b50);
	copy_le16(trailer.disk, 0);
	copy_le16(trailer.directory_start_disk, 0);
	copy_le16(trailer.entries_on_this_disk, zip_dir_entries);
	copy_le16(trailer.entries, zip_dir_entries);
	copy_le32(trailer.size, zip_dir_offset);
	copy_le32(trailer.offset, zip_offset);
	copy_le16(trailer.comment_length, sha1 ? 40 : 0);

	write_or_die(1, zip_dir, zip_dir_offset);
	write_or_die(1, &trailer, ZIP_DIR_TRAILER_SIZE);
	if (sha1)
		write_or_die(1, sha1_to_hex(sha1), 40);
}

static void dos_time(time_t *time, int *dos_date, int *dos_time)
{
	struct tm *t = localtime(time);

	*dos_date = t->tm_mday + (t->tm_mon + 1) * 32 +
	            (t->tm_year + 1900 - 1980) * 512;
	*dos_time = t->tm_sec / 2 + t->tm_min * 32 + t->tm_hour * 2048;
}

static int write_zip_archive(const struct archiver *ar,
			     struct archiver_args *args)
{
	int err;

	dos_time(&args->time, &zip_date, &zip_time);

	zip_dir = xmalloc(ZIP_DIRECTORY_MIN_SIZE);
	zip_dir_size = ZIP_DIRECTORY_MIN_SIZE;

	err = write_archive_entries(args, write_zip_entry);
	if (!err)
		write_zip_trailer(args->commit_sha1);

	free(zip_dir);

	return err;
}

static struct archiver zip_archiver = {
	"zip",
	write_zip_archive,
	ARCHIVER_WANT_COMPRESSION_LEVELS|ARCHIVER_REMOTE
};

void init_zip_archiver(void)
{
	register_archiver(&zip_archiver);
}
