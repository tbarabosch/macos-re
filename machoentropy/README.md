Simple python script for computing the entropy of all relevant sections of a Mach-O file.
A higher entropy might suggest a packed or crypted section.

python compute_entropy.py /bin/mv
__TEXT has 8192 bytes with entropy of 4.813855
__DATA has 4096 bytes with entropy of 0.325840
__LINKEDIT has 11856 bytes with entropy of 4.444262

python compute_entropy.py /Applications/Skype.app/Contents/MacOS/Skype 
__TEXT has 31965184 bytes with entropy of 6.563878
__DATA has 3067904 bytes with entropy of 3.299411
__LINKEDIT has 370384 bytes with entropy of 7.323416
