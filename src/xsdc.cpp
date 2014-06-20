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

uint32_t getDataOutputSize(uint32_t inputSize)
{
    uint32_t size;

    size = inputSize % 8;
    if (size != 0)
        return inputSize + 8 - size;
    else
        return inputSize;
}

DecrError decryptData(void *buffer, uint32_t *bufferSize, void *outputBuffer, void *key, uint32_t keyLength)
{
//     CBlowFish *cbf1 = new CBlowFish();
//     cbf1->Initialize((unsigned char *)key,32);
//     uint32_t size = cbf1->GetOutputLength(*bufferSize);
//     void *result = malloc(size);
//     cbf1->Decode((unsigned char*)buffer, (unsigned char*)outputBuffer, *bufferSize);
//     delete cbf1;
//     *bufferSize = size;
    //open encryption desciptor
    int err = 0;
    MCRYPT td = mcrypt_module_open("blowfish-compat", NULL, "ecb", NULL);
    if(td == MCRYPT_FAILED)
    {
        return DD_AO;
    }

    //set decryption key
    err = mcrypt_generic_init(td, key, keyLength, NULL);
    if(err < 0)
    {
        return DD_IE;
    }

    //decrypt
    memcpy(outputBuffer, buffer, *bufferSize);
    int offset = 0;
    int blockSize = mcrypt_enc_get_block_size(td);
    while(offset<=*bufferSize)
    {
        err = mdecrypt_generic(td, outputBuffer + offset, blockSize);
        if(err != 0)
        {
            return DD_DE;
        }
        offset += blockSize;
    }

    //close descriptor
    err = mcrypt_generic_deinit(td);
    if(err < 0)
    {
        return DD_DIE;
    }
    err = mcrypt_module_close(td);

    return DD_OK;
}

ulong countCrc(FILE *f, uint32_t hdrSize)
{
    void *buffer = malloc(0x1000);
    uLong crc = crc32(0L, Z_NULL, 0);
    fseek(f, hdrSize+4, SEEK_SET);
    size_t bytes = 0;
    while((bytes = fread(buffer, 1, 0x1000, f)) != 0)
    {
        crc = crc32(crc, (Bytef*)buffer, bytes);
    }
    free(buffer);
    return crc;
}

DecrError loadHeader(FILE *f, Header *hdr, uint32_t hdrSize, UnpackData *ud)
{
    unsigned char *data = (unsigned char *)malloc(hdrSize);
    fread(data,1,hdrSize,f);
    DecrError err = decryptData(data, &hdrSize, hdr, ud->headerKey, 32);
    free(data);
    return err;
}

