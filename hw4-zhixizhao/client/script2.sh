#!/bin/sh

# NOTE: SERVER MUST BE RUNNING IN BACKGROUND RESTART AFTER EACH SCRIPT

# START WITH ./server -n 3

echo Test2: Jobs Limit
printf "\n"

./client -j -r "ls -l"
./client -j -r "ls -l"
./client -j -r "ls -l"
echo check
./client -s 0
./client -j -r "ls -l"
echo check
./client -s 0
./client -c 2
echo check
./client -s 0
./client -x
cd ..
cd server
rm 1 2 3
rm *.err
printf "\n"

 
if test $? -eq 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"