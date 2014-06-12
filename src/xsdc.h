#include "bfsh-con/blowfish.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

typedef struct unpackdata_t
{
  uint32_t checksum;
  uint32_t xorVal;
  void *headerKey;
  void *fileNameKey;
  void *unformatted;
} UnpackData;

/*
 * xor every byte of a BUFFER by FACTOR
 */
void xorBuffer(uint8_t factor, unsigned char* buffer, uint32_t bufferSize);

/*
 * transforms edv in format "[int]^^[key2][key1][int]" into UnpackData struct
 */
void fillUnpackStruct(UnpackData* unpackData, void* edv);

/*
 * decrypts data from BUFFER of BUFFERSIZE size in bytes using KEY of length of KEYLENGTH,
 * returns buffer with decrypted data and sets BUFFERSIZE according to its size
 */
void *decryptData(void *buffer, uint32_t *bufferSize, void *key, uint32_t keyLength);

/*
 * open file to read and handle errors
 */
FILE *openFile(const char* fileName, const char* modes);