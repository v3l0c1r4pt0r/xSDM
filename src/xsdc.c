#include "xsdc.h"

void print_help(Shortness Short,char *name)
{
    if(Short == PH_SHORT)
        fprintf(stderr,"Usage: %s [-vf] [SDC-FILE]\n", name);
    else
        fprintf(
            stdout,
            "Usage: %s [OPTIONS] [SDC-FILE]\n"
            "OPTIONS can be one or more of the following\n"
//             "Mandatory arguments to long options are mandatory for short options too.\n"
            "\t-f, --force\t\tunpack file even if checksum is invalid\n"
            "\t-v, --verbose\t\tbe verbose\n"
            "\t-H, --header FILE\twrite SDC file header to FILE\n"
            "\t-h, --help\t\tprint this help and exit\n"
            "\t-V, --version\t\toutput version information and exit\n"
//             "\t-?, --??\t\ttext\n"
            ,name
        );
}

void print_version()
{
    fprintf(
        stdout,
        "%s %s\n"
        "License GPLv2+: GNU GPL version 2 or later <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>.\n"
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n\n"
        "Written by %s.\n"
	"With contribution of GMMan (reverse engineering the rest of SDC file).\n",
        PACKAGE,
        VERSION,
        "v3l0c1r4pt0r"
    );
}

void xorBuffer(uint8_t factor, unsigned char *buffer, uint32_t bufferSize)
{
    unsigned int i;
    for(i = 0; i < bufferSize; i++)
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
    *bufferSize = getDataOutputSize(*bufferSize);
    memcpy(outputBuffer, buffer, *bufferSize);
    int offset = 0;
    int blockSize = mcrypt_enc_get_block_size(td);
    while(offset<*bufferSize)
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

uint32_t countCrc(FILE *f, uint32_t hdrSize)
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
    return (uint32_t) crc;
}

DecrError loadHeader(FILE *f, Header *hdr, uint32_t hdrSize, UnpackData *ud)
{
    void *data = malloc(hdrSize);
    fread(data,1,hdrSize,f);
    DecrError err = decryptData(data, &hdrSize, hdr, ud->headerKey, 32);
    free(data);
    return err;
}

void dosPathToUnix(char* path)
{
    char *pointer = NULL;
    while((pointer = strstr(path,"\\")) != NULL)
    {
        pointer[0] = '/';
    }
}

uint64_t winTimeToUnix(uint64_t win)
{
    return (win / 10000000) - 	//granularity: 100 nansec ( * 10^2); to seconds ( * 10^-9)
           11644473600 - 	//difference between 1601 and 1970 in seconds
           5040;		//fixing
}

void unixTimeToStr(char *buffer, size_t bufSize, uint64_t time)
{
    if(bufSize < 20)
    {
        buffer[0] = '\0';
        return;
    }
    struct tm *ts = localtime(&time);
    strftime(buffer, bufSize, "%Y/%m/%d %H:%M:%S", ts);
}

int createDir(char* dir)
{
    DIR *f = NULL;
    if((f = opendir(dir)) == NULL)
    {
        if(mkdir(dir,S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH | S_IXOTH) != 0)
        {
            //mkdir failed
            if(errno == ENOENT)
            {
                size_t baselen = strlen(dir);
                char *base = (char*)malloc(baselen + 1);
                strcpy(base, dir);
                base = dirname(base);
                int ret = createDir(base);
                if(!ret)
                {
                    if(mkdir(dir,S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH | S_IXOTH) != 0)
                    {
                        // fail
                        return errno;
                    }
                    else
                    {
                        return 0;
                    }
                }
            }
            else
            {
                return errno;
            }
        }
    }
    else
    {
        // directory exists
        closedir(f);
    }
    f = NULL;
    return 0;
}

void printProgress(uint8_t progress)
{
    if(progress > 6)
        return;
    int i;
    char progressbar[7] = "      ";
    for(i = 0; i < progress; i++)
    {
        progressbar[i] = '#';
    }
    printf(" [%s]\r", progressbar);
    fflush(stdout);
}
