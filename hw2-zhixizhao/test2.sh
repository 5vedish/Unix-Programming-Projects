#!/bin/sh
echo Test2: Realloc With LKM_UNDER + LKM_INIT + LKM_OVER
printf "\n"

touch logs.csv
./realloc_mem 2> /dev/null
R=$?
cat logs.csv | cut -d ',' -f1,4
rm logs.csv
 
if test $R -eq 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"