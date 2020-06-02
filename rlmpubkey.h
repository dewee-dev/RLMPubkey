#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <io.h>
#include <sys/stat.h>


#ifdef _LINUX
static char* spilt = "/";
static char* localdir = "./";
#endif // _LINUX

#ifdef _WIN32
static char* spilt = "\\";
static char* localdir = ".\\";
#endif // _WIN32



typedef struct pubkeyinfo
{
	char filename[1024];
	int filesize;
	int offset;
	char* pubkey;
	int pubkeylen;
	char isvname[32];
	char* isvkey;
	struct pubkeyinfo* next;
} PubkeyInfo;



