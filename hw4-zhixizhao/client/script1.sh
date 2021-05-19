#!/bin/sh

# NOTE: SERVER MUST BE RUNNING IN BACKGROUND RESTART AFTER EACH SCRIPT

echo Test1: Job Submission + Display Statuses
printf "\n"

./client -j -r "ls -l"
./client -j -r "ping 8.8.8.8"
./client -j -r "ls -l"
./client -s 1 # display individually
./client -s 2
./client -s 3
./client -s 0 # display all
./client -k "2 9"
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