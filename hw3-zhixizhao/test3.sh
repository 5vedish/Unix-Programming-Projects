#!/bin/sh

echo Test3: Redirection
printf "\n"

printf "3\n2\n1" > nums.txt
./script3.sh
rm nums.txt
 
if test $? -eq 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"