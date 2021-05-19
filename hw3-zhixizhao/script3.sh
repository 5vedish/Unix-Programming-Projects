#! ./tish
touch a.txt
sort < nums.txt > a.txt 2> err.log
cat a.txt
rm a.txt
rm err.log
exit

