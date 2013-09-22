gcc -Wall -O2 -fpic -g -c breakpoint.c -o breakpoint.o
gcc -Wall -O2 -fpic -g -c l_debug.c -o l_debug.o
gcc -Wall -O2 -fpic -g -shared -o l_debug.so *.o
