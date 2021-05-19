#!/bin/sh

echo Test1: Internal External Commands
printf "\n"

./script1.sh
 
if test $? -eq 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"