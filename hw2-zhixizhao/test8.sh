#!/bin/sh
echo Test8: Free + LKF_ERROR
printf "\n"

touch logs.csv
./free_error 2> /dev/null
R=$?
rm logs.csv
 
if test $R -eq 1 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"