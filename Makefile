PROG = inkdwarf
CC = gcc
CFLAGS = -O0 -Wall -std=c99
LD = ld
LDFLAGS =

CFLAGS += -g -gpubnames -fdebug-types-section
LDFLAGS += -g

SRCS = inkdwarf.c
OBJS = inkdwarf.o

all: $(PROG)

$(PROG): $(OBJS)
	#$(LD) $(LDFLAGS) -o $(PROG) $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJS)

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	rm -f $(PROG) $(OBJS)
