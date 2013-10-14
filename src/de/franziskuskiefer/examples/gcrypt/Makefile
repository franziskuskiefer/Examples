
## Created by Anjuta

CC = gcc
CFLAGS = -g -Wall
OBJECTS = spake.o util.o test.o
INCFLAGS = 
LDFLAGS = -Wl,-rpath,/usr/local/lib -lgcrypt
LIBS = 

all: spake

spake: $(OBJECTS)
	$(CC) -o spake $(OBJECTS) $(LDFLAGS) $(LIBS)

.SUFFIXES:
.SUFFIXES:	.c .cc .C .cpp .o

.c.o :
	$(CC) -o $@ -c $(CFLAGS) $< $(INCFLAGS)

count:
	wc *.c *.cc *.C *.cpp *.h *.hpp

clean:
	rm -f *.o

.PHONY: all
.PHONY: count
.PHONY: clean
