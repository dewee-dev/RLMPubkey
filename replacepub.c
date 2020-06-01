#define  _CRT_SECURE_NO_WARNINGS
#include "rlmpubkey.h"
#include "pubkeyset.h"

/*复制文件*/
int cpfile(char* oldfile, char* newfile)
{
	FILE* oldname = fopen(oldfile,"rb");
	if (oldname ==NULL)
	{
		printf("%s 文件读取失败,跳过！\n", oldfile);
		return 0;
	}
	FILE* newname = fopen(newfile,"wb");
	if (newname == NULL)
	{
		printf("%s 文件创建失败，跳过！\n", newfile);
		return 0;
	}
	char wfbuf[1024] = { 0 };
	int nlen = 0;
	while ((nlen = fread(wfbuf,1,1024,oldname)) >0)
	{
		fwrite(wfbuf, 1, nlen, newname);
	}
	fclose(oldname);
	fclose(newname);
	return 1;
}

/*替换链表中标记的文件公钥*/
int replacepubkey(PubkeyInfo *pki)
{
	PubkeyInfo* p = pki->next;
	while (p)
	{
		char bakfilename[2000];
		sprintf(bakfilename, "%s_bak", p->filename);
		cpfile(p->filename, bakfilename);
		FILE* readfile = fopen(bakfilename, "rb");	
		FILE* wfile = fopen(p->filename, "wb");
		char* f2 = NULL;
		char* f1 = calloc(p->offset, 1);
		fread(f1, p->offset, 1, readfile);
		if (p->pubkeylen ==224)
		{
			int endlong = (p->filesize) - 224 - (p->offset);
			f2 = calloc(endlong, 1);
			fseek(readfile, 224, SEEK_CUR);
			fread(f2, endlong, 1, readfile);
			fwrite(f1, p->offset, 1, wfile);
			fwrite(pubkey224, 224, 1, wfile);
			fwrite(f2, endlong, 1, wfile);
		}
		else if(p->pubkeylen == 225)
		{
			int endlong = (p->filesize) - 225 - (p->offset);
			f2 = calloc(endlong, 1);
			fseek(readfile, 225, SEEK_CUR);
			fread(f2, endlong, 1, readfile);
			fwrite(f1, p->offset, 1, wfile);
			fwrite(pubkey225, 225, 1, wfile);
			fwrite(f2, endlong, 1, wfile);
		}
		else if (p->pubkeylen == 226)
		{
			int endlong = (p->filesize) - 226 - (p->offset);
			f2 = calloc(endlong, 1);
			fseek(readfile, 226, SEEK_CUR);
			fread(f2, endlong, 1, readfile);
			fwrite(f1, p->offset, 1, wfile);
			fwrite(pubkey226, 226, 1, wfile);
			fwrite(f2, endlong, 1, wfile);
		}
		else if (p->pubkeylen == 227)
		{ 
			int endlong = (p->filesize) - 227 - (p->offset);
			f2 = calloc(endlong, 1);
			fseek(readfile, 227, SEEK_CUR);
			fread(f2, endlong, 1, readfile);
			fwrite(f1, p->offset, 1, wfile);
			fwrite(pubkey227, 227, 1, wfile);
			fwrite(f2, endlong, 1, wfile);
		}
		printf("#######File %s Replace Success!!\n", p->filename);
		free(f1);
		free(f2);
		fclose(readfile);
		fclose(wfile);
		p = p->next;
	}
	return 0;
}

int fwnull(FILE* filename, int len)
{
	for (int i = 0; i < len; i++)
	{
		fwrite("\0", 1, 1, filename);
	}
	return 1;
}

//int createsign_bak(PubkeyInfo *pki, char* rlmsign, char* ISV)
//{
//	PubkeyInfo* p = pki->next;
//	int offset1 = 0x5d698; int offset2 = 0x5d698;
//	int offset3 = 0x6e878; int offset4 = 0x6e888;
//	int end = 0x80c00;
//	FILE* rlmsn = fopen(rlmsign, "rb");
//	char outname[50];
//	sprintf(outname, "rlmsign_%s.exe", ISV);
//	FILE* rlmsncreat = fopen(outname, "wb");
//
//	char* f1 = calloc(offset1, 1);
//	fread(f1, offset1, 1, rlmsn);
//
//	fseek(rlmsn, 0x5d87b, SEEK_SET);
//	char* f2 = calloc(offset3 - 0x5d87b,1);
//	fread(f2, offset3 - 0x5d87b, 1, rlmsn);
//
//	fseek(rlmsn, 0x6e9a8, SEEK_SET);
//	char* f3 = calloc(end - 0x6e9a8, 1);
//	fread(f3, end - 0x6e9a8, 1, rlmsn);
//
//	if (p->pubkeylen == 224)
//	{
//		fwrite(f1, offset1, 1, rlmsncreat);
//
//		fwrite(prikey224, 250, 1, rlmsncreat);
//		//227私钥长252，224私钥长250，多两位用\0充填
//		fwnull(rlmsncreat, 2);
//		//公私钥间有4个00 充填
//		fwnull(rlmsncreat, 4);
//
//		fwrite(pubkey224, 224, 1, rlmsncreat);
//		//227公钥长227，224公钥长224，多三位用\0充填
//		fwnull(rlmsncreat, 3);
//
//		fwrite(f2, offset3 - 0x5d87c, 1, rlmsncreat);
//
//		fwrite(ISV, strlen(ISV) , 1, rlmsncreat);
//		fwnull(rlmsncreat, 16 - strlen(ISV));
//
//
//		fwrite(p->isvkey, strlen(p->isvkey), 1, rlmsncreat);
//		fwnull(rlmsncreat, 288 - strlen(p->isvkey));
//
//		fwrite(f3, end - 0x6e9a8, 1, rlmsncreat);
//	}
//	else if (p->pubkeylen == 225)
//	{
//		fwrite(f1, offset1, 1, rlmsncreat);
//
//		fwrite(prikey224, 250, 1, rlmsncreat);
//		//227私钥长252
//		fwnull(rlmsncreat, 1);
//		//公私钥间有4个00 充填
//		fwnull(rlmsncreat, 4);
//
//		fwrite(pubkey224, 224, 1, rlmsncreat);
//		//227公钥长227
//		fwnull(rlmsncreat, 2);
//
//		fwrite(f2, offset3 - 0x5d87c, 1, rlmsncreat);
//
//		fwrite(ISV, strlen(ISV), 1, rlmsncreat);
//		fwnull(rlmsncreat, 16 - strlen(ISV));
//
//		fwrite(p->isvkey, strlen(p->isvkey), 1, rlmsncreat);
//		fwnull(rlmsncreat, 288 - strlen(p->isvkey));
//
//		fwrite(f3, end - 0x6e9a8, 1, rlmsncreat);
//	}
//	else if (p->pubkeylen == 226)
//	{
//		fwrite(f1, offset1, 1, rlmsncreat);
//
//		fwrite(prikey224, 250, 1, rlmsncreat);
//		fwnull(rlmsncreat, 1);
//		//公私钥间有4个00 充填
//		fwnull(rlmsncreat, 4);
//
//		fwrite(pubkey224, 224, 1, rlmsncreat);
//		fwnull(rlmsncreat, 1);
//
//		fwrite(f2, offset3 - 0x5d87c, 1, rlmsncreat);
//
//		fwrite(ISV, strlen(ISV), 1, rlmsncreat);
//		fwnull(rlmsncreat, 16 - strlen(ISV));
//
//
//		fwrite(p->isvkey, strlen(p->isvkey), 1, rlmsncreat);
//		fwnull(rlmsncreat, 288 - strlen(p->isvkey));
//
//		fwrite(f3, end - 0x6e9a8, 1, rlmsncreat);
//	}
//	else if (p->pubkeylen == 227) 
//	{
//		fseek(rlmsn, 0, SEEK_SET);
//		char* ff1 = calloc(offset3, 1);
//		fread(ff1, offset3,1, rlmsn);
//		fwrite(ff1, offset3,1, rlmsncreat);
//
//		fwrite(ISV, strlen(ISV), 1, rlmsncreat);
//		fwnull(rlmsncreat, 16 - strlen(ISV));
//
//
//		fwrite(p->isvkey, strlen(p->isvkey), 1, rlmsncreat);
//		fwnull(rlmsncreat, 288 - strlen(p->isvkey));
//
//		fwrite(f3, end - 0x6e9a8, 1, rlmsncreat);
//
//	}
//	fclose(rlmsn);
//	fclose(rlmsncreat);
//}

int createsign(PubkeyInfo* pki,unsigned char* rlmsign, char* ISV)
{
	PubkeyInfo* p = pki->next;
	int offset1 = 0x5d698; int offset2 = 0x5d698;
	int offset3 = 0x6e878; int offset4 = 0x6e888;
	int end = 0x80c00;
	//FILE* rlmsn = fopen(rlmsign, "rb");
	char outname[50];
	sprintf(outname, "rlmsign_%s.exe", ISV);
	FILE* rlmsncreat = fopen(outname, "wb");

	//char* f1 = calloc(offset1, 1);
	//fread(f1, offset1, 1, rlmsn);

	//fseek(rlmsn, 0x5d87b, SEEK_SET);
	//char* f2 = calloc(offset3 - 0x5d87b, 1);
	//fread(f2, offset3 - 0x5d87b, 1, rlmsn);

	//fseek(rlmsn, 0x6e9a8, SEEK_SET);
	//char* f3 = calloc(end - 0x6e9a8, 1);
	//fread(f3, end - 0x6e9a8, 1, rlmsn);
	unsigned char *pSign = rlmsign;
	if (p->pubkeylen == 224)
	{
		fwrite(pSign, offset1, 1, rlmsncreat);

		fwrite(prikey224, 250, 1, rlmsncreat);
		//227私钥长252，224私钥长250，多两位用\0充填
		fwnull(rlmsncreat, 2);
		//公私钥间有4个00 充填
		fwnull(rlmsncreat, 4);

		fwrite(pubkey224, 224, 1, rlmsncreat);
		//227公钥长227，224公钥长224，多三位用\0充填
		fwnull(rlmsncreat, 3);

		fwrite(pSign + 0x5d87b, offset3 - 0x5d87b, 1, rlmsncreat);

		fwrite(ISV, strlen(ISV), 1, rlmsncreat);
		fwnull(rlmsncreat, 16 - strlen(ISV));


		fwrite(p->isvkey, strlen(p->isvkey), 1, rlmsncreat);
		fwnull(rlmsncreat, 288 - strlen(p->isvkey));

		//fwrite(pSign + 0x6e9a8, end - 0x6e9a8, 1, rlmsncreat);
	}
	else if (p->pubkeylen == 225)
	{
		fwrite(pSign, offset1, 1, rlmsncreat);

		fwrite(prikey225, 250, 1, rlmsncreat);
		//227私钥长252，225私钥长250，多两位用\0充填
		fwnull(rlmsncreat, 2);
		//公私钥间有4个00 充填
		fwnull(rlmsncreat, 4);

		fwrite(pubkey225, 225, 1, rlmsncreat);
		//227公钥长227，224公钥长224，多三位用\0充填
		fwnull(rlmsncreat, 2);

		fwrite(pSign + 0x5d87b, offset3 - 0x5d87b, 1, rlmsncreat);

		fwrite(ISV, strlen(ISV), 1, rlmsncreat);
		fwnull(rlmsncreat, 16 - strlen(ISV));


		fwrite(p->isvkey, strlen(p->isvkey), 1, rlmsncreat);
		fwnull(rlmsncreat, 288 - strlen(p->isvkey));

		//fwrite(pSign + 0x6e9a8, end - 0x6e9a8, 1, rlmsncreat);
	}
	else if (p->pubkeylen == 226)
	{
		fwrite(pSign, offset1, 1, rlmsncreat);

		fwrite(prikey226, 251, 1, rlmsncreat);
		//227私钥长252，226私钥长251
		fwnull(rlmsncreat, 1);
		//公私钥间有4个00 充填
		fwnull(rlmsncreat, 4);

		fwrite(pubkey226, 226, 1, rlmsncreat);
		//227公钥长227，224公钥长224，多三位用\0充填
		fwnull(rlmsncreat, 1);

		fwrite(pSign + 0x5d87b, offset3 - 0x5d87b, 1, rlmsncreat);

		fwrite(ISV, strlen(ISV), 1, rlmsncreat);
		fwnull(rlmsncreat, 16 - strlen(ISV));


		fwrite(p->isvkey, strlen(p->isvkey), 1, rlmsncreat);
		fwnull(rlmsncreat, 288 - strlen(p->isvkey));

		//fwrite(f3, end - 0x6e9a8, 1, rlmsncreat);
	}
	else if (p->pubkeylen == 227)
	{
		fwrite(pSign, offset3, 1, rlmsncreat);

		fwrite(ISV, strlen(ISV), 1, rlmsncreat);
		fwnull(rlmsncreat, 16 - strlen(ISV));


		fwrite(p->isvkey, strlen(p->isvkey), 1, rlmsncreat);
		fwnull(rlmsncreat, 288 - strlen(p->isvkey));

		//fwrite(f3, end - 0x6e9a8, 1, rlmsncreat);

	}

	fwrite(pSign + 0x6e9a8, end - 0x6e9a8, 1, rlmsncreat);
	fclose(rlmsncreat);
	return 1;
}