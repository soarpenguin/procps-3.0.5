CC = gcc
CFLAGS = -g -Wall

all: myping
############ prog.c --> prog.o

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $^

############ prog.o --> prog

myping:   % : %.o 
	$(CC) $(LDFLAGS) -o $@ $^

