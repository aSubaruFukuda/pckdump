OBJS=main.o analyze.o print.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-g -Wall
TARGET=pcap
LDLIBS=
$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)
