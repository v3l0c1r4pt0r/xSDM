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
void *decryptData(void *buffer, uint32_t *bufferSize, void *key, uint32_t keyLength);
