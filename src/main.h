#define _FILE_OFFSET_BITS 64

#include "xsdc.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <dirent.h>
#include <zlib.h>

//flags
#define F_VERBOSE	0x01
#define F_FORCE		0x02

//return values
#define EXIT_SUCCESS	0
#define EXIT_INVALIDOPT	1
#define EXIT_TOOLESS	2

static struct option options [] =
{
  {"force", no_argument, NULL, 'f'},
  {"verbose", no_argument, NULL, 'v'},
  {"version", no_argument, NULL, 'V'},
  {"help", no_argument, NULL, 'h'},
  {0, 0, 0, 0}
};