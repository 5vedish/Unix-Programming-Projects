#!/bin/sh
echo Test13: Realloc Null
printf "\n"

touch logs.csv
./realloc_null 2> /dev/null
R=$?
rm logs.csv
 
if test $R -eq 1 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"