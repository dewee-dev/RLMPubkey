#define  _CRT_SECURE_NO_WARNINGS
#include "rlmpubkey.h"
#include "pubkeyset.h"


int cpfile(char* oldfile, char* newfile)
{
	FILE* oldname = fopen(oldfile,"rb");
	FILE* newname = fopen(newfile,"wb");
	char wfbuf[1024] = { 0 };
	int nlen = 0;
	while ((nlen = fread(wfbuf,1,1024,oldname)) >0)
	{
		fwrite(wfbuf, 1, nlen, newname);
	}
	fclose(oldname);
	fclose(newname);

}

int replacepubkey(PubkeyInfo *pki)
{
	PubkeyInfo* p = pki->next;
	while (p)
	{
		char bakfilename[210];
		sprintf(bakfilename, "%s_bak", p->filename);
		cpfile(p->filename, bakfilename);
		FILE* readfile = fopen(bakfilename, "rb");	
		FILE* wfile = fopen(p->filename, "wb");

		char* f1 = calloc(p->offset, 1);
		fread(f1, p->offset, 1, readfile);
		if (p->pubkeylen ==224)
		{
			int endlong = (p->filesize) - 224 - (p->offset);
			char *f2 = calloc(endlong, 1);
			fseek(readfile, 224, SEEK_CUR);
			fread(f2, endlong, 1, readfile);
			fwrite(f1, p->offset, 1, wfile);
			fwrite(keyArray224, 224, 1, wfile);
			fwrite(f2, endlong, 1, wfile);
		}
		else if(p->pubkeylen == 225)
		{
			int endlong = (p->filesize) - 225 - (p->offset);
			char* f2 = calloc(endlong, 1);
			fseek(readfile, 225, SEEK_CUR);
			fread(f2, endlong, 1, readfile);
			fwrite(f1, p->offset, 1, wfile);
			fwrite(keyArray225, 225, 1, wfile);
			fwrite(f2, endlong, 1, wfile);
		}
		else if (p->pubkeylen == 226)
		{
			int endlong = (p->filesize) - 226 - (p->offset);
			char* f2 = calloc(endlong, 1);
			fseek(readfile, 226, SEEK_CUR);
			fread(f2, endlong, 1, readfile);
			fwrite(f1, p->offset, 1, wfile);
			fwrite(keyArray226, 226, 1, wfile);
			fwrite(f2, endlong, 1, wfile);
		}
		else if (p->pubkeylen == 227)
		{ 
			int endlong = (p->filesize) - 227 - (p->offset);
			char* f2 = calloc(endlong, 1);
			fseek(readfile, 227, SEEK_CUR);
			fread(f2, endlong, 1, readfile);
			fwrite(f1, p->offset, 1, wfile);
			fwrite(keyArray227, 227, 1, wfile);
			fwrite(f2, endlong, 1, wfile);
		}
		printf("#######File %s Replace Success!!\n", p->filename);
		printf("RLM_LICENSE_TO_RUN\n%s\n", p->isvkey);
		
		fclose(readfile);
		fclose(wfile);
		p = p->next;
	}
	return 0;
}

int createsign()
{

}