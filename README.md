# showFalsePos
The one script in this repo is designed to be run as root on the target machine and all results and errors printed to STDOUT.

Copy the file to the target system, then run the script with the following command:

`sudo bash showfalse.sh`

The results will print to screen with colors enabled.  If you want to re-direct the output to a file instead, use the BW branch.

If you use the main branch to re-direct to a file there will be color code escape sequences in the results file that will make results difficult to read.