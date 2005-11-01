#!/bin/bash
# count lines from *.{c,h,html}, docs and Makefiles
#
# Just to have a little idea of the work in terms of lines...
# yes, it's useless, I agree :-)

wcc=`find . -name *.c`
echo .c files
echo ----------------------------------------------------------------
wc $wcc
echo

wch=`find . -name *.h`
echo .h files
echo ----------------------------------------------------------------
wc $wch
echo

#wchtml="`find . -name *.html`"
#echo HTML documentation
#echo ----------------------------------------------------------------
#wc $wchtml
#echo

wcTXT="`find . -type f -name '[A-Z][A-Z]*'`"
wctxt=`find . -name *.txt`
echo Text documentation
echo ----------------------------------------------------------------
wc $wcTXT $wctxt
echo

wcMk=`find . | egrep 'Makefile.in|configure.in'`
echo Compile scripts
echo ----------------------------------------------------------------
wc $wcMk
echo

echo Totals
echo ----------------------------------------------------------------
echo code:
wc $wcc $wch | grep total
echo compile scripts:
wc $wcMk | grep total
echo docs:
wc $wchtml $wctxt $wcTXT | grep total
echo All:
wc $wcc $wch $wcMk $wchtml $wctxt | grep total
