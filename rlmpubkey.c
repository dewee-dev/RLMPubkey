#define  _CRT_SECURE_NO_WARNINGS
#include "rlmpubkey.h"
#include "pubkeyset.h"


int replacepubkey(PubkeyInfo* pki);
int createsign(PubkeyInfo* pki, char* rlmsign, char* ISV);


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
		printf("RLM_LICENSE_TO_RUN = %s\n", p->isvkey);
		printf("offset = %d\n", p->offset);
		for (int j = 0; j < p->pubkeylen; j++)
		{
			printf("%02X:", (unsigned char)(p->pubkey[j]));
		}
		printf("\n");
		//for (size_t i = 0; i < 10; i++)
		//{
		//	if (p->offset[i] ==0)
		//	{
		//		break;
		//	}
		//	printf("offset = %d\n", p->offset[i]);
		//	printf("pubkey = %d\n", p->pubkeylen[i]);
		//	for (size_t j = 0; j < p->pubkeylen[i]; j++)
		//	{
		//		
		//		printf("%02X:", (unsigned char)(p->pubkey[i][j]));
		//	}
		//	printf("\n");
		//}

		p = p->next;
	}
	return 1;
}

int compare(char* val1, char* val2, int len)
{
	for (int i = 0; i < len; i++)
	{
		if (val1[i] !=val2[i])
		{
			return 0;
		}
	}
	return 1;
}



//公钥检索
int checkpubflag(char *buffer, long bufferlen,PubkeyInfo *pki)
{
	char* tvalue = buffer; int num = 0; int result = 0;
	for (long i = 0; i < bufferlen; i++)
	{
		if (tvalue[i] == (char)0x30 &&
			tvalue[ i + 1 ] == (char)0x81 &&
			tvalue[i + 3] == (char)0x02 &&
			(tvalue[i + 4] == (char)0x3F || tvalue[i + 4] == (char)0x40 || tvalue[i + 4] == (char)0x41)
			)
		{

			int publen = (unsigned char)tvalue[i + 2] + 3;
			char* pubkey = calloc(publen+1, 1);
			memcpy(pubkey, &tvalue[i], publen);
			if (compare(pubkey, defaultpubkey1,publen) ||
				compare(pubkey, defaultpubkey2, publen)||
				compare(pubkey, defaultpubkey3, publen)||
				compare(pubkey, pubkey224, publen)     ||
				compare(pubkey, pubkey225, publen)     ||
				compare(pubkey, pubkey226, publen)     ||
				compare(pubkey, pubkey227, publen))
			{

				i += publen;
				continue;
			}
			pki->offset = i;
			pki->pubkey = pubkey;
			pki->pubkeylen = publen;
			i += publen;
			result = 1;
		}
	}
	return result;
}

int checkisvname(char* buffer, int value,PubkeyInfo *pki)
{
	for (int i = value; i > value -32; i--)
	{
		if ((buffer[i] < 0x30) ||
			((0x39 < buffer[i]) &&(buffer[i] < 0x41)) ||
			((0x5a < buffer[i]) && (buffer[i] < 0x61)) ||
			(0x7a < buffer[i]))
		{
			if (value - (i+1) >= 2)
			{
				memcpy(pki->isvname, buffer+(i+1), value - i);
				return 1;
			}
			return 0;
		}
	}
	return 0;
}


//SIV检索
int checkisvflag(char* buffer, long bufferlen, PubkeyInfo* pki)
{
	char isvflag[5] = { 0x73,0x69,0x67,0x3d,0x22 };
	char* tvalue = buffer; int strint = 0; int endint = 0; int tmpint = 0; int strlen = 0;
	for (long i = 0; i < bufferlen; i++)
	{
		if (tvalue[i] == *(isvflag) &&
			tvalue[i + 1] == *(isvflag + 1) &&
			tvalue[i + 2] == *(isvflag + 2) &&
			tvalue[i + 3] == *(isvflag + 3) &&
			tvalue[i + 4] == *(isvflag + 4))
		{
			tmpint = i;
			while (tvalue[tmpint--] != '\0')
			{
				strint = tmpint+1;
			}

			tmpint = i;
			while (tvalue[tmpint++] != '\0')
			{
				endint = tmpint;
			}
			if (tvalue[strint] !=(char )'<')
			{
				strlen = endint - strint;
				char* isvkey = calloc(strlen+1, 1);
				memcpy(isvkey, &tvalue[strint], strlen);
				pki->isvkey = isvkey;
				/*ISV NAME*/
				while (strint--)
				{		
					//printf("%c",tvalue[strint--]);
					if (tvalue[strint] != '\0' && tvalue[strint] != 0x0a)
					{
						checkisvname(tvalue, strint, pki);
						break;
					}
				}
				
			}
			i = endint;
		}
	}
	return 1;
}


int readsubfile(char *subfile,PubkeyInfo *pk)
{
	struct stat buf;
	PubkeyInfo *pki;
	pki =init();
	stat(subfile, &buf);
	unsigned char* bsubf = calloc(buf.st_size, sizeof(char));
	FILE* subf = fopen(subfile, "rb");
	if (subf == NULL)
	{
		printf("%s文件读取失败，跳过分析.\n",subfile);
		return 0;
	}
	fread(bsubf, buf.st_size, 1, subf);
	if (checkpubflag(bsubf, buf.st_size, pki))
	{
		checkisvflag(bsubf, buf.st_size, pki);
		strcpy(pki->filename, subfile);
		pki->filesize = buf.st_size;
		pki->next = pk->next;//将最后一个next置为NULL
		pk->next = pki;//追加链表
	}
	fclose(subf);
	return 1;
}

/*遍历文件*/
int listFiles(char* dir,PubkeyInfo *pki)
{
	struct _finddata_t findData;
	
	intptr_t handle;
	char newdir[1024];
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
			char sdir[1024];
			strcpy(sdir, dir);
			strcat(sdir, findData.name);
			strcat(sdir, spilt);
			listFiles(sdir,pki);
		}
		else
		{
			char checkf[1024];
			sprintf(checkf, "%s%s", dir, findData.name);
			//CheckFile(checkf);  /**/
			if(strcmp(findData.name + strlen(findData.name) - 4, "_bak")==0)
			{
				continue;
			}
			readsubfile(checkf, pki);
		}
	} while (_findnext(handle, &findData) == 0);
	_findclose(handle);

	return 1;
}


int main_1()
{

	PubkeyInfo *pfirst = init();
	listFiles(localdir, pfirst);
	//listpubkey(pfirst);
	replacepubkey(pfirst);
	createsign(pfirst,"rlmsign.exe","lms");
	return 0;
}
