#include "xsdc.h"

void xorBuffer(uint8_t factor, unsigned char *buffer, uint32_t bufferSize)
{
    for(unsigned int i = 0; i < bufferSize; i++)
    {
        buffer[i] ^= factor;
    }
}

UnpackStatus fillUnpackStruct(UnpackData *unpackData, void *edv)
{
    UnpackData ud;
    ud.unformatted = edv;
    if(strlen((char*)edv)<0x44)
      return FUS_LNG;
    char *keyStart = strstr((char*)ud.unformatted,"^^");
    if(keyStart == NULL)
      return FUS_NFND;
    keyStart += 2;
    ud.fileNameKey = keyStart;
    ud.headerKey = keyStart+0x20;
    char *endptr = NULL;
    ud.checksum = strtoul((char*)ud.unformatted,&endptr,10);
    if(ud.unformatted == endptr)
      return FUS_NAN;
    ud.xorVal = strtoul(keyStart+0x40,&endptr,10);
    if(keyStart+0x40 == endptr)
      return FUS_NAN;
    
    //ok, copy to unpackData
    memcpy(unpackData,(void*)&ud,sizeof(UnpackData));
    return FUS_OK;
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

FILE* openFile(const char* fileName, const char* modes)
{
    FILE *f = fopen(fileName,modes);
    if(f == NULL)
    {
        //error opening a file
        perror(fileName);
        exit(errno);
    }
    return f;
}
