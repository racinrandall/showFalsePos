# showFalsePos
The one script in this repo is designed to be run as root on the target machine and all results and errors printed to a file.

Unlike the main branch, this is designed to have the results redirected to a file.

Copy the file to the target system, then run the script with the following command:

`sudo bash showfalse.sh > results.txt 2>&1`

These results will be black and white and best for redirecting to a file.  If you want colored output that is easier to read on the screen, use the main branch.  

If you use the main branch to re-direct to a file there will be color code escape sequences in the results file that will make results difficult to read.