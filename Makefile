CFLAGS=-Wall -g
all:	bfsh-con/blowfish.o main.o
	g++ $(CFLAGS) -o xSDM main.o bfsh-con/blowfish.o -lz
main.o:
	g++ $(CFLAGS) -c -o main.o main.cpp
bfsh-con/blowfish.o:
	g++ $(CFLAGS) -c -o bfsh-con/blowfish.o bfsh-con/blowfish.cpp
clean:
	rm -R *.o xSDM