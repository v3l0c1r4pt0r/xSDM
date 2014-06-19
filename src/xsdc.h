#include "bfsh-con/blowfish.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <zlib.h>
#include <gcrypt.h>

#define moreThan4gb	0xd1

//flags
#define F_VERBOSE	0x01

typedef struct __attribute__ ((__packed__)) header_t
{
  uint32_t	headerSignature;
  uint32_t	xorParam;
  uint32_t	headerSize;
  uint8_t	unknown2[0x20];
  uint32_t	compressedSize;
  uint32_t	fileSize;
  uint32_t	fileKey;
  uint32_t	unknown3[3];
  uint32_t	fileNameLength;
  uint8_t	fileName;
} Header;

typedef struct __attribute__ ((__packed__)) header_4gb_t
{
  uint32_t	headerSignature;
  uint32_t	xorParam;
  uint32_t	headerSize;
  uint8_t	unknown2[0x20];
  uint64_t	compressedSize;
  uint32_t	fileSize;
  uint32_t	fileKey;
  uint32_t	unknown3[3];
  uint32_t	fileNameLength;
  uint8_t	fileName;
} Header4gb;

typedef union
{
  Header	header;
  Header4gb	header4gb;
} HeaderUnion;

typedef struct unpackdata_t
{
  uint32_t checksum;
  uint32_t xorVal;
  void *headerKey;
  void *fileNameKey;
  void *unformatted;
} UnpackData;

typedef enum
{
  FUS_OK = 0,	//success
  FUS_NFND,	//substring '^^' not found in edv
  FUS_LNG,	//length of a string doesn't match expected length
  FUS_NAN,	//one of numbers wasn't number at all
  FUS_ERROR	//unidentified error
} UnpackStatus;

/*
 * xor every byte of a BUFFER by FACTOR
 */
void xorBuffer(uint8_t factor, unsigned char* buffer, uint32_t bufferSize);

/*
 * transforms edv in format "[int]^^[key2][key1][int]" into UnpackData struct,
 * returns FUS_OK on success and appropriate error on fail
 */
UnpackStatus fillUnpackStruct(UnpackData* unpackData, void* edv);

/*
 * decrypts data from BUFFER of BUFFERSIZE size in bytes using KEY of length of KEYLENGTH,
 * returns buffer with decrypted data and sets BUFFERSIZE according to its size
 */
void decryptData(void* buffer, uint32_t* bufferSize, void* outputBuffer, void* key, uint32_t keyLength);

/*
 * get number of bytes that need to be allocated for decryptData's output buffer
 */
uint32_t getDataOutputSize(uint32_t inputSize);

/*
 * count and return crc of sdc file's data area
 */
ulong countCrc(FILE *f, uint32_t hdrSize);

/*
 * load sdc file header from current position in F into HDR buffer
 */
void loadHeader(FILE* f, Header* hdr, uint32_t hdrSize, UnpackData* ud);