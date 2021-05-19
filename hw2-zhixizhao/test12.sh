#!/bin/sh
echo Test12: Realloc Smaller
printf "\n"

touch logs.csv
./realloc_smaller 2> /dev/null
S=$(cat logs.csv | cut -d ',' -f1,4)

S2=$(printf "record_type,line_num\n0,22\n0,23")

if [ "$S" = "$S2" ]; then
    R=0
else 
    R=1
fi
rm logs.csv

if test $R -eq 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"