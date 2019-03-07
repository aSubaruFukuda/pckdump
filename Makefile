PROGRAM=pckdump
OBJS=main.o analyze.o print.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall
LDLIBS=

$(PROGRAM):$(OBJS)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS)
	$(RM) $(OBJS)

clean:
	$(RM) $(TARGET)
