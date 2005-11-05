#!/bin/bash
# count lines from *.{c,h,html}, docs and Makefiles
#
# Just to have a little idea of the work in terms of lines...
# yes, it's useless, I agree :-)

IGNORE="\.svn"

wcc=`find . -name *.c | grep -v $IGNORE`
echo .c files
echo ----------------------------------------------------------------
wc $wcc
echo

wch=`find . -name *.h | grep -v $IGNORE`
echo .h files
echo ----------------------------------------------------------------
wc $wch
echo

wctxt="`find . -type f -name '[A-Z][A-Z]*' -o -name *.txt | grep -v $IGNORE`"
echo Text documentation
echo ----------------------------------------------------------------
wc $wctxt
echo

echo Totals
echo ----------------------------------------------------------------
echo code:
wc $wcc $wch | grep total
echo docs:
wc $wctxt | grep total
echo All:
wc $wcc $wch $wctxt | grep total
