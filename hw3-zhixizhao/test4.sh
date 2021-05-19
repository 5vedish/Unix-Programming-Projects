#!/bin/sh

echo Test4: Globbing
printf "\n"

./script4.sh
 
if test $? -eq 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"