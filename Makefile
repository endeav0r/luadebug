OBJS = breakpoint.o l_debug.o

CFLAGS = -O2 -fpic

all : l_debug

l_debug : $(OBJS)
	$(CC) -shared -o l_debug.so $(OBJS) $(CFLAGS)

%.o : %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

clean :
	rm -f *.o
	rm -f l_debug.so