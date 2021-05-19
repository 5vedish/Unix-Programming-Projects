#!/bin/sh
echo Test1: -e and -d flags cannot be supplied together
printf "\n"

./fenc -e -d infile outfile 2> /dev/null
 
if test $? != 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"

echo Test2: files not provided
printf "\n"

./fenc -e -d 2> /dev/null

if test $? != 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"

echo Test3: neither -e nor -d flags present
printf "\n"

./fenc infile outfile 2> /dev/null

if test $? != 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"

echo Test4: too few arguments
printf "\n"

./fenc -e infile 2> /dev/null

if test $? != 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"

echo Test5: too many arguments
printf "\n"

./fenc -e -v -h -D 0 -p passfile infile outfile anotherfile 2> /dev/null

if test $? != 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"

echo Test6: passing invalid -D debug values
printf "\n"

./fenc -e -D 500 infile outfile 2> /dev/null

if test $? != 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"

echo Test7: illegal arguments
printf "\n"

./fenc -e -z infile outfile 2> /dev/null

if test $? != 0 ; then
  echo this test is OK
else
  echo this test FAILED
fi
printf "\n"





