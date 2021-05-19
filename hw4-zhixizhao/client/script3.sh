#!/bin/sh

# NOTE: SERVER MUST BE RUNNING IN BACKGROUND RESTART AFTER EACH SCRIPT

echo Test3: Signals
printf "\n"

./client -j -r "ping 8.8.8.8"
sleep 1
./client -k "1 19"
sleep 1
./client -s 0
./client -k "1 18"
sleep 1
./client -s 0
./client -k "1 9"
sleep 1
./client -s 0
sleep 1
./client -x
printf "\n"
cd ..
cd server
rm 1 
rm *.err

 
if test $? -eq 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"