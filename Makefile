APP=asrepl
CC=gcc
CFLAGS=-g3 -O0 -Wall -DASSEMBLER=\"$(AS)\"
SRCS=main.c asrepl_commands.c asrepl.c assembler.c
OBJS=$(SRCS:.c=.o)
LDFLAGS=-lreadline -lkeystone 

all: $(APP)

.PHONY: sanity
sanity:
ifeq ($(AS),)
$(error Could not locate assembler, please set AS manually in the Makefile.)
endif

$(APP): sanity $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clean:
	$(RM) $(OBJS) $(APP)
