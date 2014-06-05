CFLAGS=-Wall -g
LIBS=-lz
GXX=g++
all:	bfsh-con/blowfish.o main.o xsdm.o
	$(GXX) $(CFLAGS) -o xSDM main.o bfsh-con/blowfish.o xsdm.o $(LIBS)
main.o: main.cpp
	$(GXX) $(CFLAGS) -c -o main.o main.cpp
xsdm.o: xsdm.c
	$(GXX) $(CFLAGS) -c -o xsdm.o xsdm.c
bfsh-con/blowfish.o:
	$(GXX) $(CFLAGS) -c -o bfsh-con/blowfish.o bfsh-con/blowfish.cpp
clean:
	rm -R *.o xSDM