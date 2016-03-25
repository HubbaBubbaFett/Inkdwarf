PROG    = inkdwarf
CC      = gcc
CFLAGS  = -O0 -Wall -std=c99
LD      = ld
LDFLAGS =

# debug
CFLAGS  += -g -gpubnames -fdebug-types-section -DTEST_INKDWARF
LDFLAGS += -g -rdynamic

SRCS = inkdwarf.c
OBJS = inkdwarf.o

all: $(PROG)

$(PROG): $(OBJS)
	#$(LD) $(LDFLAGS) -o $(PROG) $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJS)

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -o $@ -c $^

bear:
	@make clean
	@bear make all

clean:
	rm -f $(PROG) $(OBJS)
