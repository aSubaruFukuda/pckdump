PROGRAM=pckdump
OBJS=main.o analyze.o show.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall -DPCAP
LDLIBS=

$(PROGRAM):$(OBJS)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS)
	$(RM) $(OBJS)

clean:
	$(RM) $(PROGRAM)
