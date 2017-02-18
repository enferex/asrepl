APP=asrepl
CC=gcc
CFLAGS=-g3 -O0 -Wall
SRCS=main.c
OBJS=$(SRCS:.c=.o)
LDFLAGS=-lreadline

all: $(APP)

$(APP): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

clean:
	$(RM) $(OBJS) $(APP)
