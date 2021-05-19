#!/bin/sh
echo Test5: Middle Free Without LKF_APPROX
printf "\n"

touch logs.csv
./free_wout_approx 2> /dev/null
S=$(cat logs.csv | cut -d ',' -f1,4)

S2=$(printf "record_type,line_num\n1,20\n0,18\n")

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