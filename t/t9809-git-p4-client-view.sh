#!/bin/sh

test_description='git-p4 client view'

. ./lib-git-p4.sh

test_expect_success 'start p4d' '
	start_p4d
'

#
# Construct a client with this list of View lines
#
client_view() {
	(
		cat <<-EOF &&
		Client: client
		Description: client
		Root: $cli
		View:
		EOF
		for arg ; do
			printf "\t$arg\n"
		done
	) | p4 client -i
}

#
# Verify these files exist, exactly.  Caller creates
# a list of files in file "files".
#
check_files_exist() {
	ok=0 &&
	num=${#@} &&
	for arg ; do
		test_path_is_file "$arg" &&
		ok=$(($ok + 1))
	done &&
	test $ok -eq $num &&
	test_line_count = $num files
}

#
# Sync up the p4 client, make sure the given files (and only
# those) exist.
#
client_verify() {
	(
		cd "$cli" &&
		p4 sync &&
		find . -type f ! -name files >files &&
		check_files_exist "$@"
	)
}

#
# Make sure the named files, exactly, exist.
#
git_verify() {
	(
		cd "$git" &&
		git ls-files >files &&
		check_files_exist "$@"
	)
}

# //depot
#   - dir1
#     - file11
#     - file12
#   - dir2
#     - file21
#     - file22
test_expect_success 'init depot' '
	(
		cd "$cli" &&
		for d in 1 2 ; do
			mkdir -p dir$d &&
			for f in 1 2 ; do
				echo dir$d/file$d$f >dir$d/file$d$f &&
				p4 add dir$d/file$d$f &&
				p4 submit -d "dir$d/file$d$f"
			done
		done &&
		find . -type f ! -name files >files &&
		check_files_exist dir1/file11 dir1/file12 \
				  dir2/file21 dir2/file22
	)
'

# double % for printf
test_expect_success 'unsupported view wildcard %%n' '
	client_view "//depot/%%%%1/sub/... //client/sub/%%%%1/..." &&
	test_when_finished cleanup_git &&
	test_must_fail "$GITP4" clone --use-client-spec --dest="$git" //depot
'

test_expect_success 'unsupported view wildcard *' '
	client_view "//depot/*/bar/... //client/*/bar/..." &&
	test_when_finished cleanup_git &&
	test_must_fail "$GITP4" clone --use-client-spec --dest="$git" //depot
'

test_expect_success 'wildcard ... only supported at end of spec 1' '
	client_view "//depot/.../file11 //client/.../file11" &&
	test_when_finished cleanup_git &&
	test_must_fail "$GITP4" clone --use-client-spec --dest="$git" //depot
'

test_expect_success 'wildcard ... only supported at end of spec 2' '
	client_view "//depot/.../a/... //client/.../a/..." &&
	test_when_finished cleanup_git &&
	test_must_fail "$GITP4" clone --use-client-spec --dest="$git" //depot
'

test_expect_success 'basic map' '
	client_view "//depot/dir1/... //client/cli1/..." &&
	files="cli1/file11 cli1/file12" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'client view with no mappings' '
	client_view &&
	client_verify &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify
'

test_expect_success 'single file map' '
	client_view "//depot/dir1/file11 //client/file11" &&
	files="file11" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'later mapping takes precedence (entire repo)' '
	client_view "//depot/dir1/... //client/cli1/..." \
		    "//depot/... //client/cli2/..." &&
	files="cli2/dir1/file11 cli2/dir1/file12
	       cli2/dir2/file21 cli2/dir2/file22" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'later mapping takes precedence (partial repo)' '
	client_view "//depot/dir1/... //client/..." \
		    "//depot/dir2/... //client/..." &&
	files="file21 file22" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

# Reading the view backwards,
#   dir2 goes to cli12
#   dir1 cannot go to cli12 since it was filled by dir2
#   dir1 also does not go to cli3, since the second rule
#     noticed that it matched, but was already filled
test_expect_success 'depot path matching rejected client path' '
	client_view "//depot/dir1/... //client/cli3/..." \
		    "//depot/dir1/... //client/cli12/..." \
		    "//depot/dir2/... //client/cli12/..." &&
	files="cli12/file21 cli12/file22" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

# since both have the same //client/..., the exclusion
# rule keeps everything out
test_expect_success 'exclusion wildcard, client rhs same (odd)' '
	client_view "//depot/... //client/..." \
		    "-//depot/dir2/... //client/..." &&
	client_verify &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify
'

test_expect_success 'exclusion wildcard, client rhs different (normal)' '
	client_view "//depot/... //client/..." \
		    "-//depot/dir2/... //client/dir2/..." &&
	files="dir1/file11 dir1/file12" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'exclusion single file' '
	client_view "//depot/... //client/..." \
		    "-//depot/dir2/file22 //client/file22" &&
	files="dir1/file11 dir1/file12 dir2/file21" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'overlay wildcard' '
	client_view "//depot/dir1/... //client/cli/..." \
		    "+//depot/dir2/... //client/cli/...\n" &&
	files="cli/file11 cli/file12 cli/file21 cli/file22" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'overlay single file' '
	client_view "//depot/dir1/... //client/cli/..." \
		    "+//depot/dir2/file21 //client/cli/file21" &&
	files="cli/file11 cli/file12 cli/file21" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'exclusion with later inclusion' '
	client_view "//depot/... //client/..." \
		    "-//depot/dir2/... //client/dir2/..." \
		    "//depot/dir2/... //client/dir2incl/..." &&
	files="dir1/file11 dir1/file12 dir2incl/file21 dir2incl/file22" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'quotes on rhs only' '
	client_view "//depot/dir1/... \"//client/cdir 1/...\"" &&
	client_verify "cdir 1/file11" "cdir 1/file12" &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify "cdir 1/file11" "cdir 1/file12"
'

#
# What happens when two files of the same name are overlayed together?
# The last-listed file should take preference.
#
# //depot
#   - dir1
#     - file11
#     - file12
#     - filecollide
#   - dir2
#     - file21
#     - file22
#     - filecollide
#
test_expect_success 'overlay collision setup' '
	client_view "//depot/... //client/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		echo dir1/filecollide >dir1/filecollide &&
		p4 add dir1/filecollide &&
		p4 submit -d dir1/filecollide &&
		echo dir2/filecollide >dir2/filecollide &&
		p4 add dir2/filecollide &&
		p4 submit -d dir2/filecollide
	)
'

test_expect_success 'overlay collision 1 to 2' '
	client_view "//depot/dir1/... //client/..." \
		    "+//depot/dir2/... //client/..." &&
	files="file11 file12 file21 file22 filecollide" &&
	echo dir2/filecollide >actual &&
	client_verify $files &&
	test_cmp actual "$cli"/filecollide &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files &&
	test_cmp actual "$git"/filecollide
'

test_expect_failure 'overlay collision 2 to 1' '
	client_view "//depot/dir2/... //client/..." \
		    "+//depot/dir1/... //client/..." &&
	files="file11 file12 file21 file22 filecollide" &&
	echo dir1/filecollide >actual &&
	client_verify $files &&
	test_cmp actual "$cli"/filecollide &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files &&
	test_cmp actual "$git"/filecollide
'

test_expect_success 'overlay collision delete 2' '
	client_view "//depot/... //client/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		p4 delete dir2/filecollide &&
		p4 submit -d "remove dir2/filecollide"
	)
'

# no filecollide, got deleted with dir2
test_expect_failure 'overlay collision 1 to 2, but 2 deleted' '
	client_view "//depot/dir1/... //client/..." \
		    "+//depot/dir2/... //client/..." &&
	files="file11 file12 file21 file22" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'overlay collision update 1' '
	client_view "//depot/dir1/... //client/dir1/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		p4 open dir1/filecollide &&
		echo dir1/filecollide update >dir1/filecollide &&
		p4 submit -d "update dir1/filecollide"
	)
'

# still no filecollide, dir2 still wins with the deletion even though the
# change to dir1 is more recent
test_expect_failure 'overlay collision 1 to 2, but 2 deleted, then 1 updated' '
	client_view "//depot/dir1/... //client/..." \
		    "+//depot/dir2/... //client/..." &&
	files="file11 file12 file21 file22" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files
'

test_expect_success 'overlay collision delete filecollides' '
	client_view "//depot/... //client/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		p4 delete dir1/filecollide dir2/filecollide &&
		p4 submit -d "remove filecollides"
	)
'

#
# Overlays as part of sync, rather than initial checkout:
#   1.  add a file in dir1
#   2.  sync to include it
#   3.  add same file in dir2
#   4.  sync, make sure content switches as dir2 has priority
#   5.  add another file in dir1
#   6.  sync
#   7.  add/delete same file in dir2
#   8.  sync, make sure it disappears, again dir2 wins
#   9.  cleanup
#
# //depot
#   - dir1
#     - file11
#     - file12
#     - colA
#     - colB
#   - dir2
#     - file21
#     - file22
#     - colA
#     - colB
#
test_expect_success 'overlay sync: add colA in dir1' '
	client_view "//depot/dir1/... //client/dir1/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		echo dir1/colA >dir1/colA &&
		p4 add dir1/colA &&
		p4 submit -d dir1/colA
	)
'

test_expect_success 'overlay sync: initial git checkout' '
	client_view "//depot/dir1/... //client/..." \
		    "+//depot/dir2/... //client/..." &&
	files="file11 file12 file21 file22 colA" &&
	echo dir1/colA >actual &&
	client_verify $files &&
	test_cmp actual "$cli"/colA &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files &&
	test_cmp actual "$git"/colA
'

test_expect_success 'overlay sync: add colA in dir2' '
	client_view "//depot/dir2/... //client/dir2/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		echo dir2/colA >dir2/colA &&
		p4 add dir2/colA &&
		p4 submit -d dir2/colA
	)
'

test_expect_success 'overlay sync: colA content switch' '
	client_view "//depot/dir1/... //client/..." \
		    "+//depot/dir2/... //client/..." &&
	files="file11 file12 file21 file22 colA" &&
	echo dir2/colA >actual &&
	client_verify $files &&
	test_cmp actual "$cli"/colA &&
	(
		cd "$git" &&
		"$GITP4" sync --use-client-spec &&
		git merge --ff-only p4/master
	) &&
	git_verify $files &&
	test_cmp actual "$git"/colA
'

test_expect_success 'overlay sync: add colB in dir1' '
	client_view "//depot/dir1/... //client/dir1/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		echo dir1/colB >dir1/colB &&
		p4 add dir1/colB &&
		p4 submit -d dir1/colB
	)
'

test_expect_success 'overlay sync: colB appears' '
	client_view "//depot/dir1/... //client/..." \
		    "+//depot/dir2/... //client/..." &&
	files="file11 file12 file21 file22 colA colB" &&
	echo dir1/colB >actual &&
	client_verify $files &&
	test_cmp actual "$cli"/colB &&
	(
		cd "$git" &&
		"$GITP4" sync --use-client-spec &&
		git merge --ff-only p4/master
	) &&
	git_verify $files &&
	test_cmp actual "$git"/colB
'

test_expect_success 'overlay sync: add/delete colB in dir2' '
	client_view "//depot/dir2/... //client/dir2/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		echo dir2/colB >dir2/colB &&
		p4 add dir2/colB &&
		p4 submit -d dir2/colB &&
		p4 delete dir2/colB &&
		p4 submit -d "delete dir2/colB"
	)
'

test_expect_success 'overlay sync: colB disappears' '
	client_view "//depot/dir1/... //client/..." \
		    "+//depot/dir2/... //client/..." &&
	files="file11 file12 file21 file22 colA" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	(
		cd "$git" &&
		"$GITP4" sync --use-client-spec &&
		git merge --ff-only p4/master
	) &&
	git_verify $files
'

test_expect_success 'overlay sync: cleanup' '
	client_view "//depot/... //client/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		p4 delete dir1/colA dir2/colA dir1/colB &&
		p4 submit -d "remove overlay sync files"
	)
'

#
# Overlay tests again, but swapped so dir1 has priority.
#   1.  add a file in dir1
#   2.  sync to include it
#   3.  add same file in dir2
#   4.  sync, make sure content does not switch
#   5.  add another file in dir1
#   6.  sync
#   7.  add/delete same file in dir2
#   8.  sync, make sure it is still there
#   9.  cleanup
#
# //depot
#   - dir1
#     - file11
#     - file12
#     - colA
#     - colB
#   - dir2
#     - file21
#     - file22
#     - colA
#     - colB
#
test_expect_success 'overlay sync swap: add colA in dir1' '
	client_view "//depot/dir1/... //client/dir1/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		echo dir1/colA >dir1/colA &&
		p4 add dir1/colA &&
		p4 submit -d dir1/colA
	)
'

test_expect_success 'overlay sync swap: initial git checkout' '
	client_view "//depot/dir2/... //client/..." \
		    "+//depot/dir1/... //client/..." &&
	files="file11 file12 file21 file22 colA" &&
	echo dir1/colA >actual &&
	client_verify $files &&
	test_cmp actual "$cli"/colA &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify $files &&
	test_cmp actual "$git"/colA
'

test_expect_success 'overlay sync swap: add colA in dir2' '
	client_view "//depot/dir2/... //client/dir2/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		echo dir2/colA >dir2/colA &&
		p4 add dir2/colA &&
		p4 submit -d dir2/colA
	)
'

test_expect_failure 'overlay sync swap: colA no content switch' '
	client_view "//depot/dir2/... //client/..." \
		    "+//depot/dir1/... //client/..." &&
	files="file11 file12 file21 file22 colA" &&
	echo dir1/colA >actual &&
	client_verify $files &&
	test_cmp actual "$cli"/colA &&
	(
		cd "$git" &&
		"$GITP4" sync --use-client-spec &&
		git merge --ff-only p4/master
	) &&
	git_verify $files &&
	test_cmp actual "$git"/colA
'

test_expect_success 'overlay sync swap: add colB in dir1' '
	client_view "//depot/dir1/... //client/dir1/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		echo dir1/colB >dir1/colB &&
		p4 add dir1/colB &&
		p4 submit -d dir1/colB
	)
'

test_expect_success 'overlay sync swap: colB appears' '
	client_view "//depot/dir2/... //client/..." \
		    "+//depot/dir1/... //client/..." &&
	files="file11 file12 file21 file22 colA colB" &&
	echo dir1/colB >actual &&
	client_verify $files &&
	test_cmp actual "$cli"/colB &&
	(
		cd "$git" &&
		"$GITP4" sync --use-client-spec &&
		git merge --ff-only p4/master
	) &&
	git_verify $files &&
	test_cmp actual "$git"/colB
'

test_expect_success 'overlay sync swap: add/delete colB in dir2' '
	client_view "//depot/dir2/... //client/dir2/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		echo dir2/colB >dir2/colB &&
		p4 add dir2/colB &&
		p4 submit -d dir2/colB &&
		p4 delete dir2/colB &&
		p4 submit -d "delete dir2/colB"
	)
'

test_expect_failure 'overlay sync swap: colB no change' '
	client_view "//depot/dir2/... //client/..." \
		    "+//depot/dir1/... //client/..." &&
	files="file11 file12 file21 file22 colA colB" &&
	echo dir1/colB >actual &&
	client_verify $files &&
	test_cmp actual "$cli"/colB &&
	test_when_finished cleanup_git &&
	(
		cd "$git" &&
		"$GITP4" sync --use-client-spec &&
		git merge --ff-only p4/master
	) &&
	git_verify $files &&
	test_cmp actual "$cli"/colB
'

test_expect_success 'overlay sync swap: cleanup' '
	client_view "//depot/... //client/..." &&
	(
		cd "$cli" &&
		p4 sync &&
		p4 delete dir1/colA dir2/colA dir1/colB &&
		p4 submit -d "remove overlay sync files"
	)
'

#
# Rename directories to test quoting in depot-side mappings
# //depot
#    - "dir 1"
#       - file11
#       - file12
#    - "dir 2"
#       - file21
#       - file22
#
test_expect_success 'rename files to introduce spaces' '
	client_view "//depot/... //client/..." &&
	client_verify dir1/file11 dir1/file12 \
		      dir2/file21 dir2/file22 &&
	(
		cd "$cli" &&
		p4 open dir1/... &&
		p4 move dir1/... "dir 1"/... &&
		p4 open dir2/... &&
		p4 move dir2/... "dir 2"/... &&
		p4 submit -d "rename with spaces"
	) &&
	client_verify "dir 1/file11" "dir 1/file12" \
		      "dir 2/file21" "dir 2/file22"
'

test_expect_success 'quotes on lhs only' '
	client_view "\"//depot/dir 1/...\" //client/cdir1/..." &&
	files="cdir1/file11 cdir1/file12" &&
	client_verify $files &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	client_verify $files
'

test_expect_success 'quotes on both sides' '
	client_view "\"//depot/dir 1/...\" \"//client/cdir 1/...\"" &&
	client_verify "cdir 1/file11" "cdir 1/file12" &&
	test_when_finished cleanup_git &&
	"$GITP4" clone --use-client-spec --dest="$git" //depot &&
	git_verify "cdir 1/file11" "cdir 1/file12"
'

test_expect_success 'kill p4d' '
	kill_p4d
'

test_done
