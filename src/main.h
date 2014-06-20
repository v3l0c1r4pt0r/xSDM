#include "xsdc.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <dirent.h>

//flags
#define F_VERBOSE	0x01
#define F_FORCE		0x02
#define F_STDIO		0x04