#include "xsdm.h"

void xorBuffer(uint8_t factor, unsigned char *buffer, uint32_t bufferSize)
{
    for(unsigned int i = 0; i < bufferSize; i++)
    {
        buffer[i] ^= factor;
    }
}

void fillUnpackStruct(UnpackData *unpackData, void *edv)	//TODO: return int/enum and indicate wrong format
{
    unpackData->unformatted = edv;
    char *keyStart = strstr((char*)unpackData->unformatted,"^^")+2;
    unpackData->fileNameKey = malloc(0x20);
    strncpy((char*)unpackData->fileNameKey,keyStart,0x20);
    unpackData->headerKey = malloc(0x20);
    strncpy((char*)unpackData->headerKey,keyStart+0x20,0x20);
    unpackData->checksum = strtoul((char*)unpackData->unformatted,NULL,10);
    unpackData->xorVal = strtoul(keyStart+0x40,NULL,10);
}