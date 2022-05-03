# Kernel Programming: Rootkit
For this project, I use C to implement functions that mimics the functions of Rootkit: Hiding suspicious process so that users cannot detect what actually happened using system command like ls, ps, cat, find command.

## How I implement Rootkit?
I hide suspicious program by firstly loading original kernel settings, then load sneaky kernel settings and prevent my process from being found by users. After my process has done, it will load original kernel settings back so that users will not detect anything.


