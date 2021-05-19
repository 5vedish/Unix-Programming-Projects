#!/bin/sh
echo Test1: outfile is preserved on error
printf "\n"

echo hello > moo.txt
echo hello2 > doo.txt
echo hello2 > original.txt

echo pass > passfile.txt

./fenc -e -p passfile.txt -r moo.txt doo.txt 2> /dev/null

diff original.txt doo.txt # checking if anything has changed in output by invoking IO error

rm moo.txt
rm doo.txt
rm original.txt

rm passfile.txt

if test $? != 1 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"