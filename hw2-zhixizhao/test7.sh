#!/bin/sh
echo Test7: Free With No Malloc + LKF_UNKNOWN
printf "\n"

touch logs.csv
./free_no_malloc 2> /dev/null
S=$(cat logs.csv | cut -d ',' -f1,4)

S2=$(printf "record_type,line_num\n1,18\n")

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