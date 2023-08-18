#!/bin/bash

# line=echo '[TEST] CHALLENGE! Please send the solution for: 801'
test="$(printf '%s' '[TEST] CHALLENGE! Please send the solution for: 801')"
printf -v line "$test"
# echo $line
# python3 -c 'import sys;print(sys.argv[8])' $line
python3 -c 'import sys;e=sys.argv[8];print(eval(e.replace(e[0:48],)));' $line




# [TEST] CHALLENGE! Please send the solution for: 801