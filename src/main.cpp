#include "main.h"

int main(int argc, char **argv)
{
    if(argc<2)
    {
        printf("Usage: %s [sdc-file-name]\n",basename(argv[0]));
        return -1;
    }
    int result;
    FILE *in = fopen(argv[1],"r");
    if(in == NULL)
    {
        //error opening sdc file, exists?
        printf("While opening sdc file fopen() returned errno: %d\n",errno);
        return errno;
    }

    //open key file
    void *keyFileName = malloc(strlen(argv[1])+5);
    sprintf((char*)keyFileName,"%s.key",argv[1]);
    FILE *key = fopen((char*)keyFileName,"r");
    if(key == NULL)
    {
        //error opening key file, exists?
        printf("While opening key file fopen() returned errno: %d\n",errno);
        return errno;
    }

    //load keyFileName
    fseek(key,0,SEEK_END);
    int unformattedLength = ftell(key);
    fseek(key,0,SEEK_SET);
    void *unformatted = malloc(unformattedLength);
    fread(unformatted,1,unformattedLength,key);

    //fill unpack structure
    UnpackData unpackData;
    fillUnpackStruct(&unpackData,unformatted);

    //load header size
    uint8_t *hdrSizeBuff = (uint8_t*)malloc(4);
    fread(hdrSizeBuff,1,4,in);
    uint32_t headerSize = *(uint32_t*)hdrSizeBuff;
    free(hdrSizeBuff);
    hdrSizeBuff = NULL;

    //decode header
    Header *header;// = (Header*)malloc(headerSize);

    unsigned char *data = (unsigned char *)malloc(headerSize);
    fread(data,1,headerSize,in);
    header = (Header*)decryptData(data, &headerSize, unpackData.headerKey, 32);
    free(data);
    data = NULL;

    //decode data from header
    uint32_t fnLength = header->fileNameLength;
    data = (unsigned char*)decryptData(&header->fileName, &fnLength, unpackData.fileNameKey, 32);

    fprintf(stderr,"File path: %s\n",data);
    memcpy((void*)&header->fileName,data, fnLength);

    char *pointer = NULL;
    while((pointer = strstr((char*)&header->fileName,"\\")) != NULL)
    {
        pointer[0] = '/';
    }

    char *dirName = (char*)malloc(header->fileNameLength);
    strncpy(dirName,(char*)&header->fileName+1,header->fileNameLength);
    dirName = dirname(dirName);

    char *baseName = basename((char*)&header->fileName);

    //get sdc location
    char *sdcDir = (char*)malloc(strlen(argv[1]));
    strcpy(sdcDir,argv[1]);
    sdcDir = dirname(sdcDir);
    
    //create directory according to header
    char *outFile = (char*)malloc(strlen(sdcDir)+strlen(dirName)+2);
    sprintf(outFile,"%s/%s",sdcDir,dirName);
    DIR *f = NULL;
    if((f = opendir(outFile)) == NULL)
    {
        if(mkdir(outFile,S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH | S_IXOTH) != 0)
        {
            //mkdir failed
            printf("Directory '%s' creation failed with errno: %d\n",outFile,errno);
            return errno;
        }
    }
    else
        closedir(f);
    
    //open output file
    outFile = (char*)realloc(outFile, strlen(sdcDir)+strlen(dirName)+strlen(baseName)+3);
    sprintf(outFile,"%s/%s/%s",sdcDir,dirName,baseName);
    FILE *out = fopen(outFile, "w");
    if(out == NULL)
    {
        //error opening sdc file, exists?
        printf("While creating output file fopen() returned errno: %d\n",errno);
        return errno;
    }

    //memory cleanup
    free(outFile);
    outFile = NULL;
    free(sdcDir);
    sdcDir = NULL;
    free(dirName);
    dirName = NULL;

    //ensure we are after header
    if(int r = fseek(in,headerSize+4,SEEK_SET)!=0)
        return r;

    //create inflate struct
    z_stream stream;
    stream.next_in = Z_NULL;
    stream.avail_in = 0;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;

    //initialize stream
    int r = (int)-1;
    if(header->headerSignature == moreThan4gb)
        r = inflateInit(&stream);
    else
        r = inflateInit2_(&stream,-15,ZLIB_VERSION,(int)sizeof(z_stream));//NOTE: should be "1.2.2",0x38, or maybe not?
    if(r != Z_OK)
    {
        fprintf(stderr,"inflateInit failed with errorcode %d (%s)\n",r,stream.msg);
        return r;
    }
    //read from file
    unsigned int bytesToRead = header->compressedSize & 0x3fff;
    unsigned char *input = (unsigned char*)malloc(bytesToRead);	//NOTE: probably a bit different number
    unsigned char *output = (unsigned char*)malloc(0x4000);		//exactly
    void *tmp = malloc(bytesToRead);

    //determine file size
    unsigned int bytesRemaining = 0;
    HeaderUnion *hu = (HeaderUnion*)header;
    if(hu->header.headerSignature == moreThan4gb)
        bytesRemaining = hu->header4gb.fileSize;
    else
        bytesRemaining = hu->header.fileSize;

    fprintf(stderr,"file size has been set as %u (0x%04X), signature: 0x%02X\n",bytesRemaining,bytesRemaining,header->headerSignature);

    while(bytesRemaining != 0)
    {
        result = fread(input+stream.avail_in,1,bytesToRead-stream.avail_in,in);
        if(result == 0 && stream.avail_in == 0)	//stop only if stream iflated whole previous buffer
            return 1;				//still have bytes remaining but container end reached

        //decode
        stream.next_in = (Bytef*)input;
        stream.avail_in += result;
        stream.next_out = (Bytef*)output;
        stream.avail_out = 0x4000;
        stream.total_in = 0;
        stream.total_out = 0;
        r = inflate(&stream,0);
        if(r < Z_OK)
        {
            fprintf(stderr,"inflate failed with errorcode %d (%s)\n",r,stream.msg);
            return r;
        }

        //XOR
        xorBuffer(unpackData.xorVal % 0x100, output, stream.total_out);

        //write to file
        fwrite(output,1,stream.total_out,out);
        bytesRemaining -= stream.total_out;

        /*
        * tricky part: input buffer hadn't been fully decompressed
        * so we need to copy the rest to TMP and then at the beginning
        * of input buffer so it can be inflated, but before that we need to
        * read the rest of a chunk so its size would be STRANGESIZE
        */
        memcpy(tmp,stream.next_in,stream.avail_in);
        memcpy(input,tmp,stream.avail_in);
    }
    free(tmp);
    tmp = NULL;
    free(input);
    input = NULL;
    free(output);
    output = NULL;
    free(unpackData.unformatted);
    unpackData.unformatted = NULL;
    //FIXME: after rewriting fillUnpackStruct there should be more NULLs in it here

    //write sdc header to &2
    uint8_t *headerBuff = (uint8_t*)header;
    for(int i = 0; i < 0x200; i++)
    {
        if(i%8==0)
            fprintf(stderr,"\n%04X:\t",i);
        fprintf(stderr,"0x%02X ",headerBuff[i]);
    }
    fprintf(stderr,"\n");
//     fprintf(stderr,"crc32(0)=0x%lX\n",crc32(0,0,0));

    fclose(in);
    fclose(out);
    return 0;
}

/*
 * Roadmap:
 * * split into functions
 * - check CRC
 * - write possibility to extract more than one file
 * - unit tests
 */
