#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <io.h>
#include <sys/stat.h>


#ifdef _LINUX
char* spilt = "/";
char* localdir = "./";
#endif // _LINUX


/*
*	1、循环遍历文件，定位RLM文件
*	2、查找文件公钥信息
*/

typedef struct pubkeyinfo
{
	char filename[200];
	int offset[10];
	char* pubkey[10];
	int pubkeylen[10];
	char* isvkey;
	struct pubkeyinfo* next;
} PubkeyInfo;

int replacepubkey(PubkeyInfo *pki);