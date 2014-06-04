CFLAGS=-Wall -g
all:	bfsh-con/blowfish.o main.o xsdm.o
	g++ $(CFLAGS) -o xSDM main.o bfsh-con/blowfish.o xsdm.o -lz
main.o: main.cpp
	g++ $(CFLAGS) -c -o main.o main.cpp
xsdm.o: xsdm.c
	g++ $(CFLAGS) -c -o xsdm.o xsdm.c
bfsh-con/blowfish.o:
	g++ $(CFLAGS) -c -o bfsh-con/blowfish.o bfsh-con/blowfish.cpp
clean:
	rm -R *.o xSDM