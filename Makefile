CC=gcc
CPPFLAGS=-g -std=c++11 -Ofast -march=native -mtune=native -Wall $(FLAGS)
#CFLAGS=-g -std=c11 -Ofast -march=native -mtune=native -Wall $(FLAGS)
#CFLAGS=-std=c11 -Ofast -march=nehalem -mtune=nehalem -Wall
LDFLAGS=

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

%.o: %.cpp
	g++ $(CPPFLAGS) $< -c -o $@

all: dumps

dumps: dumps.o
	g++ $^ -o $@

