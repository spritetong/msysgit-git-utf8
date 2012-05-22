#!/bin/sh
#
# Copyright (c) 2005 Johannes Schindelin
#

test_description='Testing multi_ack pack fetching'

. ./test-lib.sh

# Test fetch-pack/upload-pack pair.

# Some convenience functions

add () {
	name=$1 &&
	text="$@" &&
	branch=`echo $name | sed -e 's/^\(.\).*$/\1/'` &&
	parents="" &&

	shift &&
	while test $1; do
		parents="$parents -p $1" &&
		shift
	done &&

	echo "$text" > test.txt &&
	git update-index --add test.txt &&
	tree=$(git write-tree) &&
	# make sure timestamps are in correct order
	test_tick &&
	commit=$(echo "$text" | git commit-tree $tree $parents) &&
	eval "$name=$commit; export $name" &&
	echo $commit > .git/refs/heads/$branch &&
	eval ${branch}TIP=$commit
}

pull_to_client () {
	number=$1 &&
	heads=$2 &&
	count=$3 &&
	test_expect_success "$number pull" '
		(
			cd client &&
			git fetch-pack -k -v .. $heads &&

			case "$heads" in
			    *A*)
				    echo $ATIP > .git/refs/heads/A;;
			esac &&
			case "$heads" in *B*)
			    echo $BTIP > .git/refs/heads/B;;
			esac &&
			git symbolic-ref HEAD refs/heads/`echo $heads \
				| sed -e "s/^\(.\).*$/\1/"` &&

			git fsck --full &&

			mv .git/objects/pack/pack-* . &&
			p=`ls -1 pack-*.pack` &&
			git unpack-objects <$p &&
			git fsck --full &&

			idx=`echo pack-*.idx` &&
			pack_count=`git show-index <$idx | wc -l` &&
			test $pack_count = $count &&
			rm -f pack-*
		)
	'
}

# Here begins the actual testing

# A1 - ... - A20 - A21
#    \
#      B1  -   B2 - .. - B70

# client pulls A20, B1. Then tracks only B. Then pulls A.

test_expect_success 'setup' '
	mkdir client &&
	(
		cd client &&
		git init &&
		git config transfer.unpacklimit 0
	) &&
	add A1 &&
	prev=1 &&
	cur=2 &&
	while [ $cur -le 10 ]; do
		add A$cur $(eval echo \$A$prev) &&
		prev=$cur &&
		cur=$(($cur+1))
	done &&
	add B1 $A1 &&
	echo $ATIP > .git/refs/heads/A &&
	echo $BTIP > .git/refs/heads/B &&
	git symbolic-ref HEAD refs/heads/B
'

pull_to_client 1st "refs/heads/B refs/heads/A" $((11*3))

test_expect_success 'post 1st pull setup' '
	add A11 $A10 &&
	prev=1 &&
	cur=2 &&
	while [ $cur -le 65 ]; do
		add B$cur $(eval echo \$B$prev) &&
		prev=$cur &&
		cur=$(($cur+1))
	done
'

pull_to_client 2nd "refs/heads/B" $((64*3))

pull_to_client 3rd "refs/heads/A" $((1*3))

test_expect_success 'single branch clone' '
	git clone --single-branch "file://$(pwd)/." singlebranch
'

test_expect_success 'single branch object count' '
	GIT_DIR=singlebranch/.git git count-objects -v |
		grep "^in-pack:" > count.singlebranch &&
	echo "in-pack: 198" >expected &&
	test_cmp expected count.singlebranch
'

test_expect_success 'clone shallow' '
	git clone --no-single-branch --depth 2 "file://$(pwd)/." shallow
'

test_expect_success 'clone shallow object count' '
	(
		cd shallow &&
		git count-objects -v
	) > count.shallow &&
	grep "^in-pack: 18" count.shallow
'

test_expect_success 'clone shallow object count (part 2)' '
	sed -e "/^in-pack:/d" -e "/^packs:/d" -e "/^size-pack:/d" \
	    -e "/: 0$/d" count.shallow > count_output &&
	! test -s count_output
'

test_expect_success 'fsck in shallow repo' '
	(
		cd shallow &&
		git fsck --full
	)
'

test_expect_success 'simple fetch in shallow repo' '
	(
		cd shallow &&
		git fetch
	)
'

test_expect_success 'no changes expected' '
	(
		cd shallow &&
		git count-objects -v
	) > count.shallow.2 &&
	cmp count.shallow count.shallow.2
'

test_expect_success 'fetch same depth in shallow repo' '
	(
		cd shallow &&
		git fetch --depth=2
	)
'

test_expect_success 'no changes expected' '
	(
		cd shallow &&
		git count-objects -v
	) > count.shallow.3 &&
	cmp count.shallow count.shallow.3
'

test_expect_success 'add two more' '
	add B66 $B65 &&
	add B67 $B66
'

test_expect_success 'pull in shallow repo' '
	(
		cd shallow &&
		git pull .. B
	)
'

test_expect_success 'clone shallow object count' '
	(
		cd shallow &&
		git count-objects -v
	) > count.shallow &&
	grep "^count: 6" count.shallow
'

test_expect_success 'add two more (part 2)' '
	add B68 $B67 &&
	add B69 $B68
'

test_expect_success 'deepening pull in shallow repo' '
	(
		cd shallow &&
		git pull --depth 4 .. B
	)
'

test_expect_success 'clone shallow object count' '
	(
		cd shallow &&
		git count-objects -v
	) > count.shallow &&
	grep "^count: 12" count.shallow
'

test_expect_success 'deepening fetch in shallow repo' '
	(
		cd shallow &&
		git fetch --depth 4 .. A:A
	)
'

test_expect_success 'clone shallow object count' '
	(
		cd shallow &&
		git count-objects -v
	) > count.shallow &&
	grep "^count: 18" count.shallow
'

test_expect_success 'pull in shallow repo with missing merge base' '
	(
		cd shallow &&
		test_must_fail git pull --depth 4 .. A
	)
'

test_expect_success 'additional simple shallow deepenings' '
	(
		cd shallow &&
		git fetch --depth=8 &&
		git fetch --depth=10 &&
		git fetch --depth=11
	)
'

test_expect_success 'clone shallow object count' '
	(
		cd shallow &&
		git count-objects -v
	) > count.shallow &&
	grep "^count: 52" count.shallow
'

test_expect_success 'clone shallow without --no-single-branch' '
	git clone --depth 1 "file://$(pwd)/." shallow2
'

test_expect_success 'clone shallow object count' '
	(
		cd shallow2 &&
		git count-objects -v
	) > count.shallow2 &&
	grep "^in-pack: 6" count.shallow2
'

test_expect_success 'clone shallow with --branch' '
	git clone --depth 1 --branch A "file://$(pwd)/." shallow3
'

test_expect_success 'clone shallow object count' '
	echo "in-pack: 12" > count3.expected &&
	GIT_DIR=shallow3/.git git count-objects -v |
		grep "^in-pack" > count3.actual &&
	test_cmp count3.expected count3.actual
'

test_expect_success 'clone shallow with detached HEAD' '
	git checkout HEAD^ &&
	git clone --depth 1 "file://$(pwd)/." shallow5 &&
	git checkout - &&
	GIT_DIR=shallow5/.git git rev-parse HEAD >actual &&
	git rev-parse HEAD^ >expected &&
	test_cmp expected actual
'

test_expect_success 'shallow clone pulling tags' '
	git tag -a -m A TAGA1 A &&
	git tag -a -m B TAGB1 B &&
	git tag TAGA2 A &&
	git tag TAGB2 B &&
	git clone --depth 1 "file://$(pwd)/." shallow6 &&

	cat >taglist.expected <<\EOF &&
TAGB1
TAGB2
EOF
	GIT_DIR=shallow6/.git git tag -l >taglist.actual &&
	test_cmp taglist.expected taglist.actual &&

	echo "in-pack: 7" > count6.expected &&
	GIT_DIR=shallow6/.git git count-objects -v |
		grep "^in-pack" > count6.actual &&
	test_cmp count6.expected count6.actual
'

test_expect_success 'shallow cloning single tag' '
	git clone --depth 1 --branch=TAGB1 "file://$(pwd)/." shallow7 &&
	cat >taglist.expected <<\EOF &&
TAGB1
TAGB2
EOF
	GIT_DIR=shallow7/.git git tag -l >taglist.actual &&
	test_cmp taglist.expected taglist.actual &&

	echo "in-pack: 7" > count7.expected &&
	GIT_DIR=shallow7/.git git count-objects -v |
		grep "^in-pack" > count7.actual &&
	test_cmp count7.expected count7.actual
'

test_expect_success 'setup tests for the --stdin parameter' '
	for head in C D E F
	do
		add $head
	done &&
	for head in A B C D E F
	do
		git tag $head $head
	done &&
	cat >input <<-\EOF
	refs/heads/C
	refs/heads/A
	refs/heads/D
	refs/tags/C
	refs/heads/B
	refs/tags/A
	refs/heads/E
	refs/tags/B
	refs/tags/E
	refs/tags/D
	EOF
	sort <input >expect &&
	(
		echo refs/heads/E &&
		echo refs/tags/E &&
		cat input
	) >input.dup
'

test_expect_success 'fetch refs from cmdline' '
	(
		cd client &&
		git fetch-pack --no-progress .. $(cat ../input)
	) >output &&
	cut -d " " -f 2 <output | sort >actual &&
	test_cmp expect actual
'

test_expect_success 'fetch refs from stdin' '
	(
		cd client &&
		git fetch-pack --stdin --no-progress .. <../input
	) >output &&
	cut -d " " -f 2 <output | sort >actual &&
	test_cmp expect actual
'

test_expect_success 'fetch mixed refs from cmdline and stdin' '
	(
		cd client &&
		tail -n +5 ../input |
		git fetch-pack --stdin --no-progress .. $(head -n 4 ../input)
	) >output &&
	cut -d " " -f 2 <output | sort >actual &&
	test_cmp expect actual
'

test_expect_success 'test duplicate refs from stdin' '
	(
	cd client &&
	test_must_fail git fetch-pack --stdin --no-progress .. <../input.dup
	) >output &&
	cut -d " " -f 2 <output | sort >actual &&
	test_cmp expect actual
'

test_done
