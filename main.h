#include "bfsh-con/blowfish.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>
#include <errno.h>

typedef struct __attribute__ ((__packed__)) header_t
{
  uint32_t	headerSignature;
  uint32_t	unknown1;
  uint32_t	entryCount;
  uint8_t	unknown2[0x20];
  uint32_t	strangeSize;
  uint32_t	fileSize;
  uint32_t	fileKey;
  uint32_t	unknown3[3];
  uint32_t	fileNameLength;
  uint8_t	fileName[0x34];
} Header;

typedef struct unpackdata_t
{
  uint32_t checksum;
  uint32_t xorVal;
  void *headerKey;
  void *fileNameKey;
  void *unformatted;
} UnpackData;