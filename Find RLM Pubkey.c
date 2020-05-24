#define  _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <io.h>
#include <sys/stat.h>

#ifdef _LINUX
char* spilt = "/";
char* localdir = "./";
#endif // _LINUX

#ifdef _WIN32
char* spilt = "\\";
char* localdir = ".\\";
#endif // _WIN32
/*
*	1、循环遍历文件，定位RLM文件
*	2、查找文件公钥信息
*/

typedef struct pubkeyinfo
{
	char* filename;
	int offset[10];
	char* pubkey[10];
	int pubkeylen[10];
	struct pubkeyinfo* next;
} PubkeyInfo;

//链表初始化
PubkeyInfo* init()
{
	return calloc(sizeof(PubkeyInfo), 1);
}

//遍历链表
int listpubkey(PubkeyInfo*list)
{
	PubkeyInfo *p = list->next;
	while (p)
	{
		printf("#######################################\n");
		printf("filename = %s\n", p->filename);
		for (size_t i = 0; i < 10; i++)
		{
			if (p->offset[i] ==0)
			{
				break;
			}
			printf("offset  = %d\n", p->offset[i]);
			printf("pubkeylen  = %d\n", p->pubkeylen[i]);
			for (size_t j = 0; j < p->pubkeylen[i]; j++)
			{
				
				printf("%02X:", (unsigned char)(p->pubkey[i][j]));
			}
			printf("\n");
		}

		p = p->next;
	}

}

int checkpubflag(char *buffer, long bufferlen,PubkeyInfo *pki)
{
	char* tvalue = buffer; int num = 0;
	for (size_t i = 0; i < bufferlen-225; i++)
	{
		//printf("%x", tvalue[i]);
		if (tvalue[i] == (char)0x30 &&
			tvalue[ i + 1 ] == (char)0x81 &&
			tvalue[i + 3] == (char)0x02 &&
			(tvalue[i + 4] == (char)0x3F || tvalue[i + 4] == (char)0x40 || tvalue[i + 4] == (char)0x41)
			)
		{
			int publen = (unsigned char)tvalue[i + 2] + 3;
			char* pubkey = calloc(publen, 1);
			memcpy(pubkey, &tvalue[i], publen);
			pki->offset[num] = i;
			pki->pubkey[num] = pubkey;
			pki->pubkeylen[num] = publen;
			num++;
			//printf("\n");
			//for (size_t j = 0; j < publen; j++)
			//{
			//	*(pubkey + j) = tvalue[i+j];	
			//	printf("%02X:", (unsigned char)tvalue[i + j]);
			//}
			//printf("\n");
		}
	}
}


int readsubfile(char *subfile,PubkeyInfo *pk)
{
	struct stat buf;
	PubkeyInfo *pki;
	pki =init();
	stat(subfile, &buf);
	unsigned char* bsubf = calloc(buf.st_size, sizeof(char));
	FILE* subf = fopen(subfile, "rb");
	fread(bsubf, buf.st_size, 1, subf);
	pki->filename = subfile;
	checkpubflag(bsubf, buf.st_size, pki);
	pki->next = pk->next;//将最后一个next置为NULL
	pk->next = pki;//追加链表
}

/*遍历文件*/
int listFiles(char* dir)
{
	struct _finddata_t findData;
	
	intptr_t handle;
	char newdir[2000];
	strcpy(newdir, dir);
	strcat(newdir, "*.*");
	handle = _findfirst(newdir, &findData);
	if (handle == -1)
	{
		return 0;
	}
	do
	{
		if (strcmp(findData.name, ".") == 0 || strcmp(findData.name, "..") == 0)
		{
			continue;
		}
		if (findData.attrib & _A_SUBDIR){
			char* sdir[2000];
			strcpy(sdir, dir);
			strcat(sdir, findData.name);
			strcat(sdir, spilt);
			listFiles(sdir);
		}
		else
		{
			char checkf[2000];
			sprintf(checkf, "%s%s", dir, findData.name);
			//CheckFile(checkf);  /**/
		}
	} while (_findnext(handle, &findData) == 0);
	_findclose(handle);

	return 1;
}




int main()
{
	PubkeyInfo *pfirst = init();
	//listFiles(localdir);
	readsubfile("lms.exe", pfirst);
	readsubfile("lms-new.exe", pfirst);
	readsubfile("rlm.exe", pfirst);
	listpubkey(pfirst);
	return 0;
}