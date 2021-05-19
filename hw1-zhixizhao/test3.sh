#!/bin/sh
echo Test1: verify same key via hashes
printf "\n"

echo hello > boo.txt
echo hello2 > foo.txt

echo pass > pass1.txt
echo pass2 > pass2.txt

./fenc -e -p pass1.txt boo.txt - | ./fenc -d -p pass2.txt - foo.txt 2> /dev/null

rm boo.txt
rm foo.txt

rm pass1.txt
rm pass2.txt

if test $? != 1 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"