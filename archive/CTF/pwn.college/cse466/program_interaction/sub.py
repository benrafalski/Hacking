from subprocess import *
import os


# rev = Popen(['rev'], stdout=PIPE)
# # rev.send(b"vfyamimk\4")
# f = open('/tmp/fif', "r")
# f2 = open("/tmp/fif2", 'w')
# bin = Popen('/challenge/embryoio_level106', stdin=f, stdout=f2)
# bin.communicate()

# for i in range(336): 
#     print("1 ")

src = '/home/ihritik/file.txt'
  
# Destination file path
dst = '/home/ihritik/Desktop/file(symlink).txt'
  
# Create a symbolic link
# pointing to src named dst
# using os.symlink() method
os.symlink("/usr/bin/cat", "")




