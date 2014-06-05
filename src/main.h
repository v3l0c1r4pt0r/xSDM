#include "xsdc.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>
#include <errno.h>
#include <libgen.h>

#define moreThan4gb	0xd1

typedef struct __attribute__ ((__packed__)) header_t
{
  uint32_t	headerSignature;
  uint32_t	unknown1;
  uint32_t	entryCount;
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
  uint32_t	unknown1;
  uint32_t	entryCount;
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