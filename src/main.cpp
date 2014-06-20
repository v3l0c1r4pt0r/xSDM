#include "main.h"

int main(int argc, char **argv)
{
    uint8_t flags = 0;
    const char *sdcFile = NULL;
    FILE *statusStream = stdout;
    if(argc == 2)
    {
        flags &= ~F_VERBOSE;
        sdcFile = argv[1];
    }
    else if(argc == 3 && strcmp(argv[1],"-v") == 0)
    {
        flags |= F_VERBOSE;
        sdcFile = argv[2];
    }
    else
    {
        fprintf(stderr,"Usage: %s [-v] [sdc-file-name]\n",basename(argv[0]));
        return -1;
    }
    int result;
    fprintf(statusStream, "Opening SDC file...\t\t");
    FILE *in = fopen(sdcFile,"r");
    if(in == NULL)
    {
        //error opening a file
        fprintf(statusStream, "[FAIL]\n");
        perror(sdcFile);
        return errno;
    }
    fprintf(statusStream, "[OK]\n");

    //open key file
    void *keyFileName = malloc(strlen(sdcFile)+5);
    sprintf((char*)keyFileName,"%s.key",sdcFile);
    FILE *key = fopen((char*)keyFileName,"r");
    if(key == NULL)
    {
        //error opening a file
        fprintf(statusStream, "[FAIL]\n");
        perror((char*)keyFileName);
        return errno;
    }

    fprintf(statusStream, "Verifying keyfile...\t\t");

    //load keyFileName
    fseek(key,0,SEEK_END);
    int unformattedLength = ftell(key);
    fseek(key,0,SEEK_SET);
    void *unformatted = malloc(unformattedLength+1);
    fread(unformatted,1,unformattedLength,key);
    ((unsigned char *)unformatted)[unformattedLength] = '\0';
    fclose(key);

    //fill unpack structure
    UnpackData unpackData;
    UnpackStatus us = fillUnpackStruct(&unpackData,unformatted);
    switch(us)
    {
    case FUS_OK:
        fprintf(statusStream, "[OK]\n");
        break;
    default:
        fprintf(statusStream, "[FAIL]\n");
        fprintf(stderr, "%s: Wrong format of a keyfile!\n", argv[0]);
        return us;
    }

    //load header size
    uint8_t *hdrSizeBuff = (uint8_t*)malloc(4);
    fread(hdrSizeBuff,1,4,in);
    uint32_t headerSize = *(uint32_t*)hdrSizeBuff;
    free(hdrSizeBuff);
    hdrSizeBuff = NULL;

    fprintf(statusStream, "Validating SDC header...\t");

    //load and decode header
    Header *header = (Header*)malloc(headerSize);
    loadHeader(in, header, headerSize, &unpackData);

    //check if valid sdc file
    fseek(in,0,SEEK_END);
    long int sdcSize = ftell(in);
    if(header->compressedSize + headerSize + 4 != sdcSize)
    {
        fprintf(statusStream, "[FAIL]\n");
        fprintf(stderr, "%s: File given is not valid SDC file or decryption key wrong\n", argv[0]);
        return -1;
    }

    fprintf(statusStream, "[OK]\n");

    //check if number of files might be more than one
    if(header->headerSize > 1)
    {
        fprintf(stderr,
                "%%DEBUG_START%%\nedv: '%s'\nheader:", unpackData.unformatted
               );
        uint8_t *headerBuff = (uint8_t*)header;
        for(int i = 0; i < 0x200; i++)
        {
            if(i%8==0)
                fprintf(stderr,"\n%04X:\t",i);
            fprintf(stderr,"0x%02X ",headerBuff[i]);
        }
        fprintf(stderr,
		"\n%%DEBUG_END%%\n%s: Warning! You have encountered cabinet with more than one file inside. This is known problem since"
		" the program is now able to unpack only first.\n Please help improving the program by opening issue on github and paste"
		" above debug information. Thank you.\n",
		argv[0]
	       );

    }

    fprintf(statusStream, "Checking file integrity...\t");

    //count crc32
    uLong crc = countCrc(in, headerSize);
    if(flags & F_VERBOSE)
        fprintf(stderr, "%s: crc32: 0x%08X; orig: 0x%08X\n", argv[0], crc, unpackData.checksum);

    //check if crc is valid
    if(crc != unpackData.checksum)
    {
        fprintf(statusStream, "[FAIL]\n");
        fprintf(
            stderr, "%s: CRC32 of sdc file did not match the one supplied in keyfile (0x%04X expected while have 0x%04X)\n",
            argv[0], unpackData.checksum, crc
        );
        return crc;
    }

    fprintf(statusStream, "[OK]\n");
    fprintf(statusStream, "Decoding file name...\t\t");

    //decode data from header
    uint32_t fnLength = header->fileNameLength;
    unsigned char *data = (unsigned char*)malloc(getDataOutputSize(header->fileNameLength));
    decryptData(&header->fileName, &fnLength, data, unpackData.fileNameKey, 32);

    fprintf(statusStream, "[OK]\n");

    if(flags & F_VERBOSE)
        fprintf(stderr,"File path: %s\n",data);
    memcpy((void*)&header->fileName,data, fnLength);

    fprintf(statusStream, "Creating directory structure...\t");

    char *pointer = NULL;
    while((pointer = strstr((char*)&header->fileName,"\\")) != NULL)
    {
        pointer[0] = '/';
    }

    void *dirName = malloc(header->fileNameLength);
    strncpy((char*)dirName,(char*)&header->fileName+1,header->fileNameLength);
    dirName = dirname((char*)dirName);

    char *baseName = basename((char*)&header->fileName);

    //get sdc location
    char *sdcDir = (char*)malloc(strlen(sdcFile));
    strcpy(sdcDir,sdcFile);
    sdcDir = dirname(sdcDir);

    //create directory according to header
    char *outFile = (char*)malloc(strlen(sdcDir)+strlen((char*)dirName)+2);
    sprintf(outFile,"%s/%s",sdcDir,dirName);
    DIR *f = NULL;
    if((f = opendir(outFile)) == NULL)
    {
        if(mkdir(outFile,S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH | S_IXOTH) != 0)
        {
            //mkdir failed
            fprintf(stderr,"%s: Directory '%s' creation failed with errno: %d\n",argv[0], outFile,errno);
            return errno;
        }
    }
    else
        closedir(f);
    f = NULL;

    fprintf(statusStream, "[OK]\n");
    fprintf(statusStream, "Unpacking file(s)...\t\t");

    //open output file
    outFile = (char*)realloc(outFile, strlen(sdcDir)+strlen((char*)dirName)+strlen(baseName)+3);
    sprintf(outFile,"%s/%s/%s",sdcDir,dirName,baseName);
    FILE *out = fopen(outFile,"w");
    if(out == NULL)
    {
        //error opening a file
        fprintf(statusStream, "[FAIL]\n");
        perror(outFile);
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
        r = inflateInit2_(&stream,-15,ZLIB_VERSION,(int)sizeof(z_stream));
    if(r != Z_OK)
    {
        fprintf(statusStream, "[FAIL]\n");
        fprintf(stderr,"inflateInit failed with errorcode %d (%s)\n",r,stream.msg);
        return r;
    }
    //read from file
    unsigned int bytesToRead = header->compressedSize & 0x3fff;
    unsigned char *input = (unsigned char*)malloc(bytesToRead);
    unsigned char *output = (unsigned char*)malloc(0x4000);
    void *tmp = malloc(bytesToRead);

    //determine file size
    unsigned int bytesRemaining = 0;
    HeaderUnion *hu = (HeaderUnion*)header;
    if(hu->header.headerSignature == moreThan4gb)
        bytesRemaining = hu->header4gb.fileSize;
    else
        bytesRemaining = hu->header.fileSize;

    if(flags & F_VERBOSE)
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
            fprintf(statusStream, "[FAIL]\n");
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
        * read the rest of a chunk so its size would be COMPRESSEDSIZE
        */
        memcpy(tmp,stream.next_in,stream.avail_in);
        memcpy(input,tmp,stream.avail_in);
    }

    fprintf(statusStream, "[OK]\n");

    free(tmp);
    tmp = NULL;
    free(input);
    input = NULL;
    free(output);
    output = NULL;
    free(unpackData.unformatted);
    unpackData.unformatted = NULL;
    unpackData.fileNameKey = NULL;
    unpackData.headerKey = NULL;

    //write sdc header to &2
    uint8_t *headerBuff = (uint8_t*)header;
    if(flags & F_VERBOSE)
    {
        for(int i = 0; i < 0x200; i++)
        {
            if(i%8==0)
                fprintf(stderr,"\n%04X:\t",i);
            fprintf(stderr,"0x%02X ",headerBuff[i]);
        }
        fprintf(stderr,"\n");
    }
    
    free(header);

    fclose(in);
    fclose(out);
    return 0;
}
