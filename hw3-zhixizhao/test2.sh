#!/bin/sh

echo Test2: Assignment And Echo
printf "\n"

./script2.sh
 
if test $? -eq 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"