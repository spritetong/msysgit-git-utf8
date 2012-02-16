#include <fcntl.h>
#include <shellapi.h>
#ifndef __XUTF8_INIT__
#include "win32.h"
#include "win32_xutf8.h"
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996)
#endif

/******************************************************************************/

#ifdef __XUTF8_ENABLED__

#ifndef __XUTF8_GITPRJ__
#define xmalloc		malloc
#define xcalloc		calloc
#define xrealloc	realloc
#define xstrdup		strdup
#endif /* __XUTF8_GITPRJ__ */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

/*******************************************************************************
 * Charset convertion
 ******************************************************************************/

#define _xutf82w(src, dst)	_xutf8_a2w(_XUTF8_CODEPAGE, src, dst, ARRAY_SIZE(dst))
#define _xw2utf8(src, dst)	_xutf8_w2a(_XUTF8_CODEPAGE, src, dst, ARRAY_SIZE(dst))

wchar_t *_xutf8_a2w(unsigned codepage, const char *src, wchar_t *dst, int dst_len)
{
	int len;

	if (!dst || dst_len <= 0)
		return NULL;

	if (src)
	{
		len = MultiByteToWideChar(codepage, 0, src, -1, dst, dst_len);
		if (len > 0)
			return dst;
	}
	dst[0] = '\0';
	return NULL;
}

char *_xutf8_w2a(unsigned codepage, const wchar_t *src, char *dst, int dst_len)
{
	int len;

	if (!dst || dst_len <= 0)
		return NULL;

	if (src)
	{
		len = WideCharToMultiByte(codepage, 0, src, -1, dst, dst_len, NULL, NULL);
		if (len > 0)
			return dst;
	}
	dst[0] = '\0';
	return NULL;
}

wchar_t *_xutf8_a2w_alloc(unsigned codepage, const char *src, wchar_t *buf, int bufsz)
{
	wchar_t *dst = NULL;
	int len;

	if (src)
	{
		len = MultiByteToWideChar(codepage, 0, src, -1, NULL, 0);
		if (len > 0)
		{
			if (buf == NULL || len > bufsz)
				dst = (wchar_t *)xmalloc(len * sizeof(wchar_t));
			else
				dst = buf;
			if (dst)
				MultiByteToWideChar(codepage, 0, src, -1, dst, len);
		}
	}
	return dst;
}

char *_xutf8_w2a_alloc(unsigned codepage, const wchar_t *src, char *buf, int bufsz)
{
	char *dst = NULL;
	int len;

	if (src)
	{
		len = WideCharToMultiByte(codepage, 0, src, -1, NULL, 0, NULL, NULL);
		if (len > 0)
		{
			if (buf == NULL || len > bufsz)
				dst = (char *)xmalloc(len * sizeof(*dst));
			else
				dst = buf;
			if (dst)
				WideCharToMultiByte(codepage, 0, src, -1, dst, len + 1, NULL, NULL);
		}
	}
	return dst;
}

size_t _xutf8_str2hex(const char *p, char **end)
{
	size_t val;
	UINT digit;
	for (val = 0; ; p++)
	{
		if (*p >= '0' && *p <= '9')        
			digit = *p - '0';
		else if (*p >= 'a' && *p <= 'f')
			digit = *p - ('a' - 10);
		else if (*p >= 'A' && *p <= 'F')
			digit = *p - ('A' - 10);
		else
			break;
		val = (val << 4) + digit;
	}
	if (end)
		*end = (char *)p;
	return val;
}

char *_xutf8_hex2str(char *p, size_t value, size_t width)
{
	char buf[16];
	size_t num = 0, digit;
	do
	{
		digit = value & 0x0F;
		buf[num++] = (char)(digit + (digit < 10 ? '0' : ('A' - 10)));
		value >>= 4;
	} while (value != 0);
	while (num < width--)
		*p++ = '0';
	while (num > 0)
		*p++ = buf[--num];
	*p = '\0';
	return p;
}

/*******************************************************************************
 * Quick Sort
 ******************************************************************************/

#define QSORT_WIDTH						sizeof(void*)
#define QSORT_CUTOFF					8
#define QSORT_STKSIZ					(8 * sizeof(void*) - 2)
#define QSORT_COMPARE(a, b) 			stricmp(*(char **)(a), *(char **)(b))
#define QSORT_SWAP(a, b)				qsort_swap(a, b, width)
#define QSORT_SHORTSORT(lo, hi, width)	qsort_shortsort(lo, hi, width)

static __inline void qsort_swap(char *a, char *b, size_t width)
{
#ifdef QSORT_WIDTH

	char *tmp;
	tmp = *(char **)a;
	*(char **)a = *(char **)b;
	*(char **)b = tmp;

#else /* !QSORT_WIDTH */

	char tmp;
    if (a != b)
    {
        while (width--)
        {
            tmp = *a;
            *a++ = *b;
            *b++ = tmp;
        }
    }

#endif /* QSORT_WIDTH */
}

static void qsort_shortsort(char *lo, char *hi, size_t width)
{
    char *p, *max;

    while (hi > lo)
    {
        max = lo;
        for (p = lo + width; p <= hi; p += width)
        {
            if (QSORT_COMPARE(p, max) > 0)
                max = p;
        }
        QSORT_SWAP(max, hi);
        hi -= width;
    }
}

void _xutf8_qsort(void *base, size_t num, size_t width)
{
    char *lo, *hi;
    char *mid;
    char *loguy, *higuy;
    size_t size;
    char *lostk[QSORT_STKSIZ], *histk[QSORT_STKSIZ];
    int stkptr;

#ifdef QSORT_WIDTH
#define width QSORT_WIDTH
#endif

    if (num < 2)
        return;

    stkptr = 0;

    lo = (char *)base;
    hi = (char *)base + width * (num-1);

recurse:

    size = (hi - lo) / width + 1;

    if (size <= QSORT_CUTOFF)
    {
        qsort_shortsort(lo, hi, width);
    }
    else
    {
        mid = lo + (size / 2) * width;

        if (QSORT_COMPARE(lo, mid) > 0)
        {
            QSORT_SWAP(lo, mid);
        }
        if (QSORT_COMPARE(lo, hi) > 0)
        {
            QSORT_SWAP(lo, hi);
        }
        if (QSORT_COMPARE(mid, hi) > 0)
        {
            QSORT_SWAP(mid, hi);
        }

        loguy = lo;
        higuy = hi;

        for (;;)
        {
            if (mid > loguy)
            {
                do
                {
                    loguy += width;
                } while (loguy < mid && QSORT_COMPARE(loguy, mid) <= 0);
            }
            if (mid <= loguy)
            {
                do
                {
                    loguy += width;
                } while (loguy <= hi && QSORT_COMPARE(loguy, mid) <= 0);
            }

            do
            {
                higuy -= width;
            } while (higuy > mid && QSORT_COMPARE(higuy, mid) > 0);

            if (higuy < loguy)
                break;

            QSORT_SWAP(loguy, higuy);

            if (mid == higuy)
                mid = loguy;
        }

        higuy += width;
        if (mid < higuy)
        {
            do
            {
                higuy -= width;
            } while (higuy > mid && QSORT_COMPARE(higuy, mid) == 0);
        }
        if (mid >= higuy)
        {
            do
            {
                higuy -= width;
            } while (higuy > lo && QSORT_COMPARE(higuy, mid) == 0);
        }

        if ( higuy - lo >= hi - loguy )
        {
            if (lo < higuy)
            {
                lostk[stkptr] = lo;
                histk[stkptr] = higuy;
                ++stkptr;
            }

            if (loguy < hi)
            {
                lo = loguy;
                goto recurse;
            }
        }
        else
        {
            if (loguy < hi)
            {
                lostk[stkptr] = loguy;
                histk[stkptr] = hi;
                ++stkptr;
            }

            if (lo < higuy)
            {
                hi = higuy;
                goto recurse;
            }
        }
    }

    if (--stkptr >= 0)
    {
        lo = lostk[stkptr];
        hi = histk[stkptr];
        goto recurse;
    }

#ifdef QSORT_WIDTH
#undef width
#endif
}

/*******************************************************************************
 * Memory Pool
 ******************************************************************************/

#define _MEM_ALIGN	(sizeof(void*) * 2)
#define _MEM_MIN	32
#define _MEM_FREE	((mem_pool_t *)NULL)

typedef struct _mem_pool_struct  mem_pool_t;
typedef struct _mem_block_struct mem_block_t;

#define _mem_pool_lock_init(pool)	(void)0
#define _mem_pool_lock_uninit(pool)	(void)0
#define _mem_pool_lock(pool)		(void)0
#define _mem_pool_unlock(pool)		(void)0

struct _mem_block_struct
{
	mem_block_t *next_block;
	mem_pool_t  *pool_ptr;
};

struct _mem_pool_struct
{
	char		*pool_addr;
	size_t		pool_size;
	size_t		free_size;
	size_t		min_size;
	size_t		fragment_num;
	mem_block_t	*search;
};

void mem_pool_init(mem_pool_t *pool, void *pool_addr, size_t pool_size)
{
	char *start, *end;
	mem_block_t *block;
	
	start = (char *)(((size_t)pool_addr + (_MEM_ALIGN - 1)) / _MEM_ALIGN * _MEM_ALIGN);
	end = (char *)(((size_t)pool_addr + pool_size) / _MEM_ALIGN * _MEM_ALIGN);

	pool->pool_addr = (char *)pool_addr;
	pool->pool_size = end - start;
	pool->min_size = (_MEM_MIN + _MEM_ALIGN - 1) / _MEM_ALIGN * _MEM_ALIGN;

	/* Initial pool has two memory block: Head and Tail. */
	pool->fragment_num = 2;
	pool->free_size = pool->pool_size - sizeof(mem_block_t);

	block = (mem_block_t *)start;
	pool->search = block;
	/* Head is marked as FREE. */
	block->pool_ptr = _MEM_FREE;
	/* Head's next block is Tail. */
	block = block->next_block = (mem_block_t *)end - 1;

	/* Tail's next block is head. */
	block->next_block = (mem_block_t *)start;
	/* Tail is marked as ALLOCATED. */
	block->pool_ptr = pool;

	/* Initialize lock. */
	_mem_pool_lock_init(pool);
}

static void *_mem_pool_alloc(mem_pool_t *pool, size_t size)
{
	mem_block_t *free, *block;
	size_t free_size, count;

	/* Adjuct required memory size. */
	size += sizeof(mem_block_t);
	size = (size + (_MEM_ALIGN - 1)) / _MEM_ALIGN * _MEM_ALIGN;

	if (size > pool->free_size)
		return NULL;

	count = pool->fragment_num + 1;
	block = pool->search;
	free = NULL;
	while (count--)
	{
		if (block->pool_ptr == _MEM_FREE)
		{
			if (free)
			{
				/* Merge 2 neighbor unallocated blocks. */
				free->next_block = block->next_block;
				pool->fragment_num--;
			}
			else
			{
				/* Update search pointer. */
				pool->search = free = block;
			}
			free_size = (char *)free->next_block - (char *)free;
			if (free_size >= size)
			{
				if (free_size - size >= pool->min_size)
				{
					/* Split into 2 blocks. */
					pool->fragment_num++;
					block = (mem_block_t *)((char *)free + size);
					block->next_block = free->next_block;
					block->pool_ptr = _MEM_FREE;
					free->next_block = block;
				}
				else
					size = free_size;
				/* Save the pool pointer into the block head, so that it is marked as allocated. */
				free->pool_ptr = pool;
				/* Update pool info. */
				pool->free_size -= size;
				return free + 1;
			}
		}
		else
		{
			free = NULL;
		}
		block = block->next_block;
	}
	return NULL;
}

void *mem_pool_alloc(mem_pool_t *pool, size_t size)
{
	void *ptr = NULL;
	if (pool)
	{
		_mem_pool_lock(pool);
		ptr = _mem_pool_alloc(pool, size);
		_mem_pool_unlock(pool);
	}
	return ptr;
}

void mem_pool_free(void *memory)
{
	mem_block_t *block = (mem_block_t *)memory;
	mem_pool_t *pool;
	if (block)
	{
		block--;
		pool = block->pool_ptr;
		if ((pool != _MEM_FREE) && (pool != NULL))
		{
			_mem_pool_lock(pool);

			/* Mark the memory block as free. */
			block->pool_ptr = _MEM_FREE;
			/* Update pool info. */
			pool->free_size += (char *)block->next_block - (char *)block;
			pool->search = block;

			_mem_pool_unlock(pool);
		}
	}
}

void *mem_pool_realloc(void *memory, size_t new_size)
{
	mem_block_t *block = (mem_block_t *)memory;
	mem_pool_t *pool;
	size_t old_size;
	void *ptr;

	if (block == NULL)
		return NULL;
	block--;
	pool = block->pool_ptr;
	if ((pool == _MEM_FREE) || (pool == NULL))
		return NULL;

	_mem_pool_lock(pool);

	old_size = (char *)block->next_block - (char *)memory;
	if (old_size == new_size)
	{
		ptr = memory;
		goto done;
	}

	/* Mark the memory block as free. */
	block->pool_ptr = _MEM_FREE;
	/* Update pool info. */
	pool->free_size += (char *)block->next_block - (char *)block;

	/* Decrease the fragment number to prevent from merging this block. */
	pool->fragment_num--;

	/* Start search from this block. */
	pool->search = block;
	/* Allocate memory. */
	ptr = _mem_pool_alloc(pool, new_size);

	/* Restore the fragment number. */
	pool->fragment_num++;

	/* If memory pointer is not changed, return directly. */
	if (ptr == memory)
		goto done;

	/* No enough memory, we do allocate by the old size.
	   It is sure to succeed and return the old memory pointer. */
	if (ptr == NULL)
	{
		/* Start search from this block. */
		pool->search = block;
		_mem_pool_alloc(pool, old_size)/* == memory */;
		goto done;
	}

	/* Another memory block is allocated, so remark the old memory block as allocated. */
	block->pool_ptr = pool;
	pool->free_size -= (char *)block->next_block - (char *)block;

done:
	_mem_pool_unlock(pool);
	if (ptr != NULL && ptr != memory)
	{
		/* Copy data, then free the old memory block. */
		memcpy(ptr, memory, old_size);
		mem_pool_free(memory);
	}
	return ptr;
}

/*******************************************************************************
 * Process Environment
 ******************************************************************************/

typedef struct _xutf8_env_struct
{
	mem_pool_t	pool;
	char		**tab;
	int			count;
	int			capacity;
} xutf8_env_t;

typedef struct _xutf8_env_hdr_struct
{
	HANDLE		hsem;
	HANDLE		hmap;
	void		*poolbuf;
	xutf8_env_t *env;
} xutf8_env_hdr_t;

static const char _xutf8_env_guid[] = "{196D57D9-0717-4F20-95DD-58D0297A402C}";

static xutf8_env_t *_xutf8_environ;
static HANDLE _xutf8_env_sem;

#define _xutf8_env_malloc(size)		mem_pool_alloc(&_xutf8_environ->pool, size)
#define _xutf8_env_realloc(p, size)	((p) ? mem_pool_realloc(p, size) : \
										   mem_pool_alloc(&_xutf8_environ->pool, size))
#define _xutf8_env_free(p)			mem_pool_free(p)

static char **_xutf8_clonewenv(xutf8_env_t **ppdst, wchar_t *src)
{
	xutf8_env_t *dst;
	char **dst_entry;
	wchar_t *src_ptr;
	int count, size;
	
	if ((ppdst == NULL) || ((dst = *ppdst) == NULL))
		return NULL;

	if (dst->tab)
	{
		/* Free all old variables. */
		dst_entry = dst->tab;
		while (*dst_entry)
			_xutf8_env_free(*dst_entry++);
		dst->tab[0] = NULL;
		dst->count = 0;
	}

	if (src == NULL)
	{
		/* Free the environment control block. */
		if (dst->tab)
		{
			/* Free memory pool. */
			_xutf8_env_free(dst->tab);
			dst->tab = NULL;
			dst->capacity = 0;
			/* Free memory pool. */
			LocalFree(dst);
			*ppdst = dst = NULL;
			/* Release the lock. */
			CloseHandle((HANDLE)InterlockedExchangePointer((void**)&_xutf8_env_sem, NULL));
		}
		return NULL;
	}

	/* Get the number of variables. */
	for (count = 0, src_ptr = src; ; src_ptr++)
	{
		if (*src_ptr == '\0')
		{
			if (src_ptr == src)
				break;
			count++;
			if (*++src_ptr == '\0')
				break;
		}
	}

	if (dst->capacity < count)
	{
		size = count + 1 + count / 2;
		if (size < _XUTF8_DEFENVNUM)
			size = _XUTF8_DEFENVNUM;
		dst_entry = (char **)_xutf8_env_realloc(dst->tab, size * sizeof(char *));
		if (dst_entry == NULL)
			goto done;
		dst_entry[0] = NULL;
		dst->tab = dst_entry;
		dst->capacity = size - 1;
	}

	/* Clone environment variable table. */
	src_ptr = src;
	dst_entry = dst->tab;
	while (count--)
	{
		if (*src_ptr != '=')
		{
			size = WideCharToMultiByte(_XUTF8_CODEPAGE, 0, src_ptr, -1, NULL, 0, NULL, NULL);
			if ((size <= 0) || (*dst_entry = (char *)_xutf8_env_malloc(size)) == NULL)
				break;
			WideCharToMultiByte(_XUTF8_CODEPAGE, 0, src_ptr, -1,
				*dst_entry, size, NULL, NULL);
			dst_entry++;
			dst->count++;
		}
		while (*src_ptr++) ;
	}
	*dst_entry = NULL;

	/* Sort the table. */
	_xutf8_qsort(dst->tab, dst->count, sizeof(dst->tab[0]));

done:
	return dst->tab;
}

static int _xutf8_env_lookup(xutf8_env_t *env, const char *name, int *insert_pos)
{
	size_t l, m, h;
	char **tab;
	const char *entry, *pname;
	char centry, cname;

	if (env == NULL || name == NULL)
		return -1;

	tab = env->tab;
	l = 0;
	h = env->count;
	while (l < h)
	{
		m = (l + h) / 2;

		/* Compare entry and name case-insensitively. */
		entry = *(env->tab + m);
		pname = name;
		do
		{
			centry = *entry++;
			cname  = *pname++;
			if (cname == '\0')
			{
				if (centry == '=')
					return (int)m;
			}
			if (centry >= 'A' && centry <= 'Z')
				centry += 'a' - 'A';
			if (cname >= 'A' && cname <= 'Z')
				cname += 'a' - 'A';
		} while (centry == cname);

		if (centry > cname)
			h = m;
		else
			l = m + 1;
	}
	if (insert_pos)
		*insert_pos = (int)l;
	return -1;
}

static int _xutf8_env_set(xutf8_env_t *env, const char *name, const char *value)
{
	char **entry, *p;
	int index, ipos, count;

	if (env == NULL || name == NULL || name[0] == '\0')
		return -1;

	index = _xutf8_env_lookup(env, name, &ipos);
	if (index >= 0)
	{
		/* The variable has existed. */

		entry = env->tab + index;
		if (value != NULL && *value != '\0')
		{
			/* Update the value. */
			count = (int)strlen(name) + 1;
			p = *entry;
			if (strcmp(p + count, value) != 0)
			{
				p = (char *)_xutf8_env_realloc(p, count + strlen(value) + 1);
				if (p == NULL)
					return -1;
				*entry = p;
				strcpy(p + count, value);
			}
		}
		else
		{
			/* Remove the variable. */
			_xutf8_env_free(*entry);
			memcpy(entry, entry + 1, (env->count - index) * sizeof(char *));
			env->count--;
		}
	}
	else if (value != NULL && *value != '\0')
	{
		/* The variable has not existed. */

		if (env->count == env->capacity)
		{
			/* Table grows. */
			count = env->count;
			count += count / 2;
			entry = (char **)_xutf8_env_realloc(env->tab, count * sizeof(char *));
			if (entry == NULL)
				return -1;
			env->tab = entry;
			env->capacity = count - 1;
		}

		/* Allocate variable string. */
		count = (int)strlen(name);
		index = (int)strlen(value);
		p = (char *)_xutf8_env_malloc(count + index + 2);
		if (p == NULL)
			return -1;

		/* Add a new variable. */
		entry = env->tab + ipos;
		memmove(entry + 1, entry, (env->count - ipos + 1) * sizeof(char *));
		memcpy(p, name, count);
		*(p + count) = '=';
		memcpy(p + count + 1, value, index + 1);
		*entry = p;
		env->count++;

		/* Return index. */
		index = ipos;
	}
	return index;
}

static void _xutf8_env_lock(xutf8_env_t **ppenv)
{
	char buf[64], *p;
	wchar_t *wenv;
	HANDLE sem = NULL, hmap;
	xutf8_env_t *env = NULL;
	xutf8_env_hdr_t *hdr = NULL;
	const size_t pool_size = _XUTF8_EVNPOOLSIZE;

	sem = (HANDLE)InterlockedCompareExchangePointer((void**)&_xutf8_env_sem, NULL, NULL);

	/* Get the lock if it exists. Otherwize, create it. */
	if (sem == NULL || WaitForSingleObject(sem, INFINITE) != WAIT_OBJECT_0)
	{
		/* Make unique semaphore name. Format: "%s-%.8X-SEM". */
		p = buf;
		strcpy(p, _xutf8_env_guid);
		p += strlen(p);
		_xutf8_hex2str(p, GetCurrentProcessId(), sizeof(DWORD) * 2);
		p += strlen(p);
		strcpy(p, "-SEM");

		sem = CreateSemaphoreA(NULL, 0, 1, buf);
		if (sem == NULL)
			return;
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			/* Obtain the semaphore if it has existed already. */
			WaitForSingleObject(sem, INFINITE);
			CloseHandle(sem);
			sem = NULL;

			/* Get the environment control block from the shared memory. */
			strcpy(p, "-MAP");
			hmap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
									  PAGE_READWRITE,
									  0, pool_size, buf);
			if (hmap != NULL)
			{
				hdr = (xutf8_env_hdr_t *)MapViewOfFile(hmap, FILE_MAP_ALL_ACCESS,
													   0, 0, pool_size);
				if (hdr)
				{
					if ((env = hdr->env) != NULL)
					{
						*ppenv = env;
						(void)InterlockedExchangePointer((void **)&_xutf8_env_sem, hdr->hsem);
					}
					UnmapViewOfFile(hdr);
				}
				CloseHandle(hmap);
			}
		}
		else
		{
			(void)InterlockedExchangePointer((void **)&_xutf8_env_sem, sem);
		}
	}

	if ((env = *ppenv) == NULL)
	{
		/* Make unique file mapping name. Format: "%s-%.8X-MAP". */
		p = buf;
		strcpy(p, _xutf8_env_guid);
		p += strlen(p);
		_xutf8_hex2str(p, GetCurrentProcessId(), sizeof(DWORD) * 2);
		p += strlen(p);
		strcpy(p, "-MAP");

		/* Allocate shared memory. */
		hmap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
									PAGE_READWRITE,
									0, pool_size, buf);
		if (hmap != NULL)
		{
			hdr = (xutf8_env_hdr_t *)MapViewOfFile(hmap, FILE_MAP_ALL_ACCESS,
													0, 0, pool_size);
			if (hdr)
			{
				hdr->hsem     = _xutf8_env_sem;
				hdr->env      = (xutf8_env_t *)(hdr + 1);
				hdr->hmap     = hmap;
				hdr->poolbuf  = hdr;

				/* Initialize memory pool and UTF-8 environemnt control block. */
				env = *ppenv  = hdr->env;
				env->tab      = NULL;
				env->count    = 0;
				env->capacity = 0;
				mem_pool_init(&env->pool, env + 1, pool_size - sizeof(xutf8_env_hdr_t) - sizeof(xutf8_env_t));
				if ((wenv = GetEnvironmentStringsW()) != NULL)
				{
					_xutf8_clonewenv(ppenv, wenv);
					FreeEnvironmentStringsW(wenv);
				}
			}
			else
				CloseHandle(hmap);
		}
	}
}

static void _xutf8_env_unlock(xutf8_env_t *env)
{
	ReleaseSemaphore(_xutf8_env_sem, 1, NULL);
}

/*******************************************************************************
 * MINGW API Wrappers
 ******************************************************************************/

static __inline void xutf8_FindDataW2Utf8(LPWIN32_FIND_DATAW wfdata, LPWIN32_FIND_DATAA afdata)
{
	afdata->dwFileAttributes = wfdata->dwFileAttributes;
	afdata->ftCreationTime   = wfdata->ftCreationTime;
	afdata->ftLastAccessTime = wfdata->ftLastAccessTime;
	afdata->ftLastWriteTime  = wfdata->ftLastWriteTime;
	afdata->nFileSizeHigh    = wfdata->nFileSizeHigh;
	afdata->nFileSizeLow     = wfdata->nFileSizeLow;
#ifdef _WIN32_WCE
    afdata->dwOID            = wfdata->dwOID;
#else
	afdata->dwReserved0      = wfdata->dwReserved0;
	afdata->dwReserved1      = wfdata->dwReserved1;
#endif
	_xutf8_w2a(_XUTF8_CODEPAGE, wfdata->cFileName,
		afdata->cFileName, ARRAY_SIZE(afdata->cFileName));
#ifndef _WIN32_WCE
	_xutf8_w2a(_XUTF8_CODEPAGE, wfdata->cAlternateFileName,
		afdata->cAlternateFileName, ARRAY_SIZE(afdata->cAlternateFileName));
#endif
}

HANDLE WINAPI xutf8_FindFirstFileA(LPCSTR lpFileName,
								   LPWIN32_FIND_DATAA lpFindFileData)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	WIN32_FIND_DATAW wfdata;
	HANDLE ret;
	ret = FindFirstFileW(_xutf82w(lpFileName, wstr1),
						 lpFindFileData ? &wfdata : NULL);
	if (ret != INVALID_HANDLE_VALUE)
		xutf8_FindDataW2Utf8(&wfdata, lpFindFileData);
	return ret;
}

BOOL WINAPI xutf8_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
	WIN32_FIND_DATAW wfdata;
	BOOL ret;
	ret = FindNextFileW(hFindFile, (lpFindFileData ? &wfdata : NULL));
	if (ret)
		xutf8_FindDataW2Utf8(&wfdata, lpFindFileData);
	return ret;
}

BOOL WINAPI xutf8_GetFileAttributesExA(LPCSTR lpFileName,
									   GET_FILEEX_INFO_LEVELS fInfoLevelId,
									   PVOID lpFileInformation)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return GetFileAttributesExW(_xutf82w(lpFileName, wstr1), fInfoLevelId, lpFileInformation);
}

DWORD WINAPI xutf8_GetFileAttributesA(LPCSTR lpFileName)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return GetFileAttributesW(_xutf82w(lpFileName, wstr1));
}

BOOL WINAPI xutf8_SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return SetFileAttributesW(_xutf82w(lpFileName, wstr1), dwFileAttributes);
}

BOOL WINAPI xutf8_MoveFileExA(LPCSTR lpExistingFileName,
							  LPCSTR lpNewFileName,
							  DWORD dwFlags)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[_XUTF8_MAXWPATH];
	return MoveFileExW(_xutf82w(lpExistingFileName, wstr1),
		_xutf82w(lpNewFileName, wstr2), dwFlags);
}

#if (_WIN32_WINNT >= 0x0500)
int WINAPI xutf8_CreateHardLinkA(LPCSTR filename, LPCSTR existingFilename,
								 LPSECURITY_ATTRIBUTES securityAttributes)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[_XUTF8_MAXWPATH];
	return CreateHardLinkW(_xutf82w(filename, wstr1),
		_xutf82w(existingFilename, wstr2), securityAttributes);
}
#endif

HANDLE WINAPI xutf8_CreateFileA(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return CreateFileW(_xutf82w(lpFileName, wstr1),
			  dwDesiredAccess,
			  dwShareMode,
			  lpSecurityAttributes,
			  dwCreationDisposition,
			  dwFlagsAndAttributes,
			  hTemplateFile);
}

BOOL WINAPI xutf8_CreateProcessA(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	PVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	STARTUPINFOW si;
	STARTUPINFOA *sa = lpStartupInfo;
	BOOL ret;
	wchar_t *lpwszDesktop, *lpwszTitle, *lpwszAppName, *lpwszCmdLine, *lpwszCurDir, *lpwEnviron;
	char *p;
	int cnt;
	DWORD lasterr;

	if (sa == NULL)
		return FALSE;

	lpwszDesktop = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, sa->lpDesktop, NULL, 0);
	lpwszTitle   = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, sa->lpTitle, NULL, 0);
	lpwszAppName = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, lpApplicationName, NULL, 0);
	lpwszCmdLine = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, lpCommandLine, NULL, 0);
	lpwszCurDir  = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, lpCurrentDirectory, NULL, 0);

	/* Convert environment block. */
	lpwEnviron   = NULL;
	if (lpEnvironment && !(dwCreationFlags & CREATE_UNICODE_ENVIRONMENT))
	{
		p = (char *)lpEnvironment;
		while (1)
		{
			if (*p++ == '\0')
				if (*p++ == '\0')
					break;
		}
		cnt = MultiByteToWideChar(_XUTF8_CODEPAGE, 0,
				(char *)lpEnvironment, (int)(p - (char *)lpEnvironment), NULL, 0) + 1;
		if (cnt > 0)
		{
			if ((lpwEnviron = (wchar_t *)xmalloc(cnt * sizeof(wchar_t))) != NULL)
			{
				cnt = MultiByteToWideChar(_XUTF8_CODEPAGE, 0,
						(char *)lpEnvironment, (int)(p - (char *)lpEnvironment), lpwEnviron, cnt);
				if (cnt > 0)
				{
					dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
				}
				else
				{
					free(lpwEnviron);
					lpwEnviron = NULL;
				}
			}
		}
	}
	if (lpwEnviron == NULL)
		lpwEnviron = (wchar_t *)lpEnvironment;

	/* Convert startupinfo. */
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.lpDesktop = lpwszDesktop;
	si.lpTitle = lpwszTitle;
	si.dwX = sa->dwX;
	si.dwY = sa->dwY;
	si.dwXSize = sa->dwXSize;
	si.dwYSize = sa->dwYSize;
	si.dwXCountChars = sa->dwXCountChars;
	si.dwYCountChars = sa->dwYCountChars;
	si.dwFillAttribute = sa->dwFillAttribute;
	si.dwFlags = sa->dwFlags;
	si.wShowWindow = sa->wShowWindow;
	si.hStdInput = sa->hStdInput;
	si.hStdOutput = sa->hStdOutput;
	si.hStdError = sa->hStdError;

	ret = CreateProcessW(
		lpwszAppName,
		lpwszCmdLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpwEnviron,
		lpwszCurDir,
		&si,
		lpProcessInformation);
	lasterr = GetLastError();

	free(lpwszDesktop);
	free(lpwszTitle);
	free(lpwszAppName);
	free(lpwszCmdLine);
	free(lpwszCurDir);
	if (lpwEnviron != (wchar_t *)lpEnvironment)
		free(lpwEnviron);

	SetLastError(lasterr);
	return ret;
}

DWORD WINAPI xutf8_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize)
{
	int index;
	char *str;
	DWORD ret = 0;
	DWORD lasterr = ERROR_ENVVAR_NOT_FOUND;

	if (lpName == NULL)
		goto done;

	_xutf8_env_lock(&_xutf8_environ);

	index = _xutf8_env_lookup(_xutf8_environ, lpName, NULL);
	if (index >= 0)
	{
		str = _xutf8_environ->tab[index];
		str = strchr(str, '=') + 1;
		ret = (DWORD)strlen(str);
		if (lpBuffer != NULL && nSize > ret)
		{
			strcpy(lpBuffer, str);
			lasterr = ERROR_SUCCESS;
		}
		else
		{
			ret++;
			lasterr = ERROR_INSUFFICIENT_BUFFER;
		}
	}
	else
	{
		if (lpBuffer != NULL && nSize > 0)
			lpBuffer[0] = '\0';
	}

	_xutf8_env_unlock(_xutf8_environ);

done:
	SetLastError(lasterr);
	return ret;
}

BOOL WINAPI xutf8_SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue)
{
	wchar_t namebuf[_XUTF8_DEFENVNAM];
	wchar_t valuebuf[_XUTF8_DEFENVVAL];
	wchar_t *name, *val;
	BOOL ret = FALSE;
	DWORD lasterr = ERROR_NOT_ENOUGH_MEMORY;

	if (lpName == NULL)
	{
		lasterr = ERROR_INVALID_NAME;
		goto done;
	}

#if (_XUTF8_USE_WENV)
	if (lpValue == NULL)
		lpValue = "";
#else /* !_XUTF8_USE_WENV */
	if (lpValue != NULL && lpValue[0] == '\0')
		lpValue = NULL;
#endif /* _XUTF8_USE_WENV */

	name = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, lpName, namebuf, ARRAY_SIZE(namebuf));
	if (lpValue)
		val = _xutf8_a2w_alloc(_XUTF8_CODEPAGE, lpValue, valuebuf, ARRAY_SIZE(valuebuf));
	else
		val = NULL;
	if (name)
	{
#if (_XUTF8_USE_WENV)
		ret = !_wputenv_s(name, val);
		if (ret)
			lasterr = ERROR_SUCCESS;
#else /* !_XUTF8_USE_WENV */
		ret = SetEnvironmentVariableW(name, val);
		lasterr = ret ? ERROR_SUCCESS : GetLastError();
#endif /* _XUTF8_USE_WENV */
	}
	if (name != namebuf)
		free(name);
	if (val != valuebuf)
		free(val);

	if (ret)
	{
		_xutf8_env_lock(&_xutf8_environ);
		ret = _xutf8_env_set(_xutf8_environ, lpName, lpValue) >= 0 ? TRUE : FALSE;
		_xutf8_env_unlock(_xutf8_environ);
		lasterr = ret ? ERROR_SUCCESS : ERROR_NOT_ENOUGH_MEMORY;
	}

done:
	SetLastError(lasterr);
	return ret;
}

BOOL WINAPI xutf8_SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue)
{
	char namebuf[_XUTF8_DEFENVNAM];
	char valuebuf[_XUTF8_DEFENVVAL];
	char *name, *val;
	BOOL ret = FALSE;
	DWORD lasterr = ERROR_NOT_ENOUGH_MEMORY;

	if (lpName == NULL)
	{
		lasterr = ERROR_INVALID_NAME;
		goto done;
	}

#if (_XUTF8_USE_WENV)
	if (lpValue == NULL)
		lpValue = L"";
	if (_wputenv_s(lpName, lpValue) == 0)
#else /* !_XUTF8_USE_WENV */
	if (lpValue != NULL && lpValue[0] == '\0')
		lpValue = NULL;
	if (SetEnvironmentVariableW(lpName, lpValue))
#endif /* _XUTF8_USE_WENV */
	{
		name = _xutf8_w2a_alloc(_XUTF8_CODEPAGE, lpName, namebuf, ARRAY_SIZE(namebuf));
		if (lpValue)
			val = _xutf8_w2a_alloc(_XUTF8_CODEPAGE, lpValue, valuebuf, ARRAY_SIZE(valuebuf));
		else
			val = NULL;
		if (name)
		{
			_xutf8_env_lock(&_xutf8_environ);
			ret = _xutf8_env_set(_xutf8_environ, name, val) >= 0 ? TRUE : FALSE;
			_xutf8_env_unlock(_xutf8_environ);
			if (ret)
				lasterr = ERROR_SUCCESS;
		}
		if (name != namebuf)
			free(name);
		if (val != valuebuf)
			free(val);
	}

done:
	SetLastError(lasterr);
	return ret;
}

/******************************************************************************/

int xutf8_unlink(const char *pathname)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wunlink(_xutf82w(pathname, wstr1));
}

int xutf8_rmdir(const char *pathname)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wrmdir(_xutf82w(pathname, wstr1));
}

int xutf8_mkdir(const char *path)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wmkdir(_xutf82w(path, wstr1));
}

int xutf8_open(const char *filename, int oflags, ...)
{
	va_list args;
	unsigned mode;
	wchar_t wstr1[_XUTF8_MAXWPATH];

	va_start(args, oflags);
	mode = va_arg(args, int);
	va_end(args);

	return _wopen(_xutf82w(filename, wstr1), oflags, mode);
}

FILE *xutf8_fopen(const char *filename, const char *otype)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[20];
	return _wfopen(_xutf82w(filename, wstr1), _xutf82w(otype, wstr2));
}

FILE *xutf8_freopen(const char *filename, const char *otype, FILE *stream)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[20];
	return _wfreopen(_xutf82w(filename, wstr1), _xutf82w(otype, wstr2), stream);
}

char *xutf8_getcwd(char *pointer, int len)
{
	wchar_t *ret;
	wchar_t wstr1[_XUTF8_MAXWPATH];
	ret = _wgetcwd(wstr1, ARRAY_SIZE(wstr1));
	if (!ret)
		return NULL;
	return _xutf8_w2a(_XUTF8_CODEPAGE, ret, pointer, len);
}

int xutf8_rename(const char *pold, const char *pnew)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	wchar_t wstr2[_XUTF8_MAXWPATH];
	return _wrename(_xutf82w(pold, wstr1), _xutf82w(pnew, wstr2));
}

int xutf8_chmod(const char *filename, int pmode)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wchmod(_xutf82w(filename, wstr1), pmode);
}

int xutf8_access(const char *filename, int pmode)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _waccess(_xutf82w(filename, wstr1), pmode);
}

int xutf8_chdir(const char *path)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
	return _wchdir(_xutf82w(path, wstr1));
}

char *xutf8_mktemp(char *stemplate)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
#ifdef _MSC_VER
	if (_wmktemp_s(_xutf82w(stemplate, wstr1), _XUTF8_MAXWPATH) != 0)
#else
	if (_wmktemp(_xutf82w(stemplate, wstr1)) == NULL)
#endif
	{
		errno = EINVAL;
		return NULL;
	}
	_xutf8_w2a(_XUTF8_CODEPAGE, wstr1, stemplate, (int)strlen(stemplate) + 1);
	return stemplate;
}

int xutf8_mktemp_s(char *stemplate, size_t size)
{
	wchar_t wstr1[_XUTF8_MAXWPATH];
#ifdef _MSC_VER
	if (_wmktemp_s(_xutf82w(stemplate, wstr1), _XUTF8_MAXWPATH) != 0)
#else
	if (_wmktemp(_xutf82w(stemplate, wstr1)) == NULL)
#endif
	{
		errno = EINVAL;
		return EINVAL;
	}
	_xutf8_w2a(_XUTF8_CODEPAGE, wstr1, stemplate, (int)size);
	return 0;
}

char **xutf8_environ(void)
{
	char **env;

	_xutf8_env_lock(&_xutf8_environ);
	env = _xutf8_environ->tab;
	_xutf8_env_unlock(_xutf8_environ);

	if (env == NULL)
		errno = EINVAL;
	return env;
}

char *xutf8_getenv(const char *name)
{
	int index;
	char *ret = NULL;

	_xutf8_env_lock(&_xutf8_environ);
	index = _xutf8_env_lookup(_xutf8_environ, name, NULL);
	if (index >= 0)
		if ((ret = strchr(_xutf8_environ->tab[index], '=')) != NULL)
			ret++;
	_xutf8_env_unlock(_xutf8_environ);

	if (ret == NULL)
		errno = EINVAL;
	return ret;
}

int xutf8_getenv_s(size_t *pReturnValue, char* buffer, size_t sizeInBytes,
				   const char *varname)
{
	int ret = EINVAL;
	
	if ((pReturnValue == NULL) ||
		(buffer == NULL && sizeInBytes > 0) ||
		(varname == NULL))
	{
		goto done;
	}

	*pReturnValue = xutf8_GetEnvironmentVariableA(varname, buffer, (DWORD)sizeInBytes);
	if (*pReturnValue > 0 && *pReturnValue <= sizeInBytes)
		ret = 0;

done:
	if (ret != 0)
		errno = ret;
	return ret;
}

int xutf8_putenv(const char *envstring)
{
	char namebuf[_XUTF8_DEFENVNAM], *name;
	const char *val;
	int ret;

	if (envstring == NULL)
	{
		ret = EINVAL;
		goto done;
	}

	/* Get value */
	for (val = envstring; ; )
	{
		if (*val == '\0')
		{
			ret = EINVAL;
			goto done;
		}
		if (*val++ == '=')
			break;
	}

	/* Duplicate name. */
	if (val - envstring > ARRAY_SIZE(namebuf))
		name = (char *)xmalloc((val - envstring) * sizeof(namebuf[0]));
	else
		name = namebuf;
	if (name == NULL)
	{
		ret = ENOMEM;
		goto done;
	}
	memcpy(name, envstring, (val - envstring) * sizeof(namebuf[0]));
	name[val - envstring - 1] = '\0';

	ret = xutf8_putenv_s(name, val);

	if (name != namebuf)
		free(name);

done:
	if (ret != 0)
		errno = ret;
	return ret;
}

int xutf8_putenv_s(const char *name, const char *value)
{
	if (!xutf8_SetEnvironmentVariableA(name, value))
	{
		errno = EINVAL;
		return EINVAL;
	}
	return 0;
}

int xutf8_wputenv(const wchar_t *envstring)
{
	wchar_t namebuf[_XUTF8_DEFENVNAM], *name;
	const wchar_t *val;
	int ret;

	if (envstring == NULL)
	{
		ret = EINVAL;
		goto done;
	}

	/* Get value */
	for (val = envstring; ; )
	{
		if (*val == '\0')
		{
			ret = EINVAL;
			goto done;
		}
		if (*val++ == '=')
			break;
	}

	/* Duplicate name. */
	if (val - envstring > ARRAY_SIZE(namebuf))
		name = (wchar_t *)xmalloc((val - envstring) * sizeof(namebuf[0]));
	else
		name = namebuf;
	if (name == NULL)
	{
		ret = ENOMEM;
		goto done;
	}
	memcpy(name, envstring, (val - envstring) * sizeof(namebuf[0]));
	name[val - envstring - 1] = '\0';

	ret = xutf8_wputenv_s(name, val);

	if (name != namebuf)
		free(name);

done:
	if (ret != 0)
		errno = EINVAL;
	return ret;
}

int xutf8_wputenv_s(const wchar_t *name, const wchar_t *value)
{
	if (!xutf8_SetEnvironmentVariableW(name, value))
	{
		errno = EINVAL;
		return EINVAL;
	}
	return 0;
}

/******************************************************************************/

static void xutf8_startup(int argc, char **argv)
{
	wchar_t wpgm[_XUTF8_MAXWPATH];
	wchar_t **wargv;
	int n, i;

	wargv = CommandLineToArgvW(GetCommandLineW(), &n);
	if (wargv == NULL)
		return;

	/* Copy executable name to argv[0] */
	wpgm[0] = '\0';
	GetModuleFileNameW(NULL, wpgm, ARRAY_SIZE(wpgm));
	if (wpgm[0])
		argv[0] = _xutf8_w2a_alloc(_XUTF8_CODEPAGE, wpgm, NULL, 0);

	/* Copy arguments. */
	if (n > argc)
		n = argc;
	for (i = 1; i < n; i++)
		argv[i] = _xutf8_w2a_alloc(_XUTF8_CODEPAGE, wargv[i], NULL, 0);
	for (; i < argc; i++)
		argv[i] = xstrdup("");
	LocalFree(wargv);
}

#else /* !__XUTF8_ENABLED__ */

#define xutf8_startup(argc, argv)	(void)0

#endif /* __XUTF8_ENABLED__ */

#ifdef _MSC_VER
#pragma warning(pop)
#endif
