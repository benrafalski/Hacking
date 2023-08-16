# this chall doesn't let you see the source code -> need to find the password using gdb

# 1. run the binary on gdb
# 2. set breakpoint at *main-0x115
# 3. set through the break point when it is hit until there is a strcmp that happens
# 4. the secret password in the second argument in the strcmp