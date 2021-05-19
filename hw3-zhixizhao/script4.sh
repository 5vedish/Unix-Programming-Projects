#! ./tish
touch 1.f
touch 2.f
touch a.txt
touch b.txt
echo *.f *.txt
ls -l *.f *.txt
rm 1.f
rm 2.f
rm a.txt
rm b.txt
exit

