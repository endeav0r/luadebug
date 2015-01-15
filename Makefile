OBJS = breakpoint.o l_debug.o

CFLAGS = -O2 -fpic

all : l_debug

l_debug : $(OBJS)
	$(CC) -shared -o ldebug.so $(OBJS) $(CFLAGS)

%.o : %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

clean :
	rm -f *.o
	rm -f ldebug.so