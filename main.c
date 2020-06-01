#define  _CRT_SECURE_NO_WARNINGS
#include "rlmpubkey.h"
#include <Windows.h>
#include "resource.h"

int replacepubkey(PubkeyInfo* pki);
int createsign(PubkeyInfo* pki, char* rlmsign, char* ISV);
PubkeyInfo* init();
int listFiles(char* dir, PubkeyInfo* pki);

int help() 
{
	printf("使用说明\n");
	printf("RLM 12新版本 RLM_ISV_NAME 参数被隐藏，需要自己通过许可文件去查找\n");
	
	printf("RLMpubkey.exe ISV\n");
	printf("例如：一段许可文件内容如下,ISV 为demo，命令为 \"RLMpubkey.exe demo\"\n");
	printf("HOST THIS_HOST 68f7283e08b7 \nISV demo \nLICENSE demo f1 15.1 permanent 1 hostid = 68f7283e08b7 ...\n");
	printf("\n\n\n###########作者：xiaolei ###########\n");
	return 0;
}

int freelist(PubkeyInfo* pki)
{
	PubkeyInfo* tmp =pki->next,*tmq;
	for (; tmp != NULL;)
	{
		tmq = tmp;
		tmp = tmp->next;
		free(tmq);
	}
	return 1;
}

int main(int argc, char* argv[])
{
	//if (argc ==1 || argc >2 )
	//{
	//	help();
	//	return 0;
	//}

	PubkeyInfo* pfirst = init();
	/*检索需要替换的公钥问题*/
	listFiles(localdir, pfirst);
	if (pfirst->next ==NULL)
	{
		printf("没有需要替换的文件，软件退出\n");
		return 0;
	}
	/*替换文件公钥*/
	replacepubkey(pfirst);
	/*rc 资源加载*/
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_EXE1), TEXT("EXE"));
	DWORD dwSize = SizeofResource(NULL, hRsrc);
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	LPVOID pBuffer = LockResource(hGlobal);
	/**/
	//createsign(pfirst, (unsigned char *)pBuffer, argv[1]);
	createsign(pfirst, (unsigned char*)pBuffer, "izero");
	FreeResource(hGlobal);
	freelist(pfirst);
	return 1;
}