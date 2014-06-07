#include "xsdc.h"
#include <stdio.h>

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

void *decryptData(void *buffer, uint32_t *bufferSize, void *key, uint32_t keyLength)
{
//     printf("buffer: 0x%04x (%s)\n",buffer,buffer);
//     printf("key: 0x%04x (%s)\n",key,key);
    CBlowFish *cbf1 = new CBlowFish();
    cbf1->Initialize((unsigned char *)key,32);
    uint32_t size = cbf1->GetOutputLength(*bufferSize);
    void *result = malloc(size);
    cbf1->Decode((unsigned char*)buffer, (unsigned char*)result, *bufferSize);
//     delete cbf1;
    *bufferSize = size;
//     printf("result: 0x%04x (%s), size: %d\n",result,result,size);
    return result;
}
