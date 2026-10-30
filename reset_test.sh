#!/bin/sh
# reset_test.sh - rebuild the Test folder to its original state and take a fresh baseline
cd "$HOME/itec624" || exit 1
rm -rf Test
mkdir -p Test/records
echo "Payroll export - Q3"   > Test/1.txt
echo "Customer contact list" > Test/2.txt
echo "Server config v1"      > Test/3.txt
echo "Patient intake form"   > "Test/records/intake form.txt"
ln -s 1.txt Test/latest_payroll
./ids.sh -c VERI1
sleep 1   # make sure later changes get a different timestamp
