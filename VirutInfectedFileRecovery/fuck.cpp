//fucked by baoshijin
//last modified date: 2019.1.9



#include "virut_sig.h"
#include "include/capstone.h"

#pragma comment(lib,"capstone_dll.lib")

#define DEBUG 1      //���������Ϣ
#define MYTEST 1     //���������������ܵ�, �ǾͰ������Ϊ0, һ��һ��ȥ����, ����û��û�����ı���



//�Ƚ�tocmp�����ֽ�, whatwewantд�������ַ��� 
//����ʮ������, ��Сд����ν, �ո�����ν, ���ֽ�ƥ��, �ʺ�ƥ������.
//����arg2: "68 ?? ?? ?? ??"
int sig_cmp(const BYTE* tocmp, const char* whatwewant)
{
	int i = 0, j = 0;
	while (whatwewant[j])
	{
		if (whatwewant[j] == ' ')
		{
			++j;
			continue;
		}
		if (whatwewant[j] == '?')
		{
			++i, ++j;
			continue;
		}
		BYTE temp = tocmp[i / 2];  //��ǰҪ�Ƚϵ��ֽ�
		if (whatwewant[j] >= 0x30 && whatwewant[j] <= 0x39)
		{
			if (i % 2 == 0)  //˵���ǱȽϸ�λ
			{
				if (((temp & 0xf0) >> 4) != (whatwewant[j] - 0x30))
				{
					return 0;
				}
			}
			else
			{
				if (((temp & 0x0f)) != (whatwewant[j] - 0x30))
				{
					return 0;
				}
			}
		}else if (whatwewant[j] >= 0x41 && whatwewant[j] <= 0x7a)
		{
			BYTE fuck = whatwewant[j] >= 0x61 ? whatwewant[j] - 0x20 : whatwewant[j]; // ת���ɴ�дͳһ����

			if (i % 2 == 0)
			{
				if (((temp & 0xf0) >> 4) != (fuck - 0x41 + 0xa))
				{
					return 0;
				}
			}
			else
			{
				if (((temp & 0x0f)) != (fuck - 0x41 + 0xa))
				{
					return 0;
				}
			}
		}

		++i, ++j; //��һ��

	}// end of while

	return TRUE;
}


int checksecname(char* tempname)
{
	int l = 0;
	bool flag;
	do
	{
		flag = tempname[l] >= 0x61 && tempname[l] <= 0x7a;
		++l;
	} while (flag);

	if (l == 7 + 1)
	{
		return 1;
	}
	return 0;

}

DWORD RVA2FO(PIMAGE_SECTION_HEADER pish, int nNumOfSections, DWORD dwRVA)
{
	int i = 0;
	for (; i < nNumOfSections; ++i)
	{
		if ((dwRVA >= pish[i].VirtualAddress) && (dwRVA < pish[i].VirtualAddress + pish[i].Misc.VirtualSize))
		{
			return dwRVA - pish[i].VirtualAddress + pish[i].PointerToRawData;
		}
	}
	if (i == nNumOfSections)
	{
		return 0;  //û�ҵ�
	}
	return 0;
}

PIMAGE_SECTION_HEADER FindRVASection(PIMAGE_SECTION_HEADER pish, int nNumOfSections, DWORD dwRVA)
{
	int i = 0;
	for (; i < nNumOfSections; ++i)
	{
		if ((dwRVA >= pish[i].VirtualAddress) && (dwRVA < pish[i].VirtualAddress + pish[i].Misc.VirtualSize))
		{
			return &pish[i];
		}
	}
	if (i == nNumOfSections)
	{
		return 0;  //û�ҵ�
	}
	return 0;
}

int DoSectionCheck(PIMAGE_SECTION_HEADER pish, int nNumOfSections)
{
	if (nNumOfSections == 1)
	{
		return 0;
	}
	for (int i = 0; i < nNumOfSections - 1; ++i)
	{
		if (pish[i].VirtualAddress + pish[i].Misc.VirtualSize > pish[i + 1].VirtualAddress)
		{
			return 0;
		}
	}
	return 1;
}


DWORD sig_denied_0x20[] =
{
	0x336e6957, 0
};

DWORD sig_confirmed_x20[] =
{
	0x248b5400,0x5bf31a54,0x1a6679f7,0x1de86992,
	0x2b284c31,0x3a4b4308,0x4cd54dad,0x4ce7ef58,
	0x4f551cb8,0x5a006a10,0x5ae868ff,0x5bf31a54,
	0x5d2e6a5b,0x6ce4acce,0x6e890200,0x6eb474d8,
	0x7a9ef856,0x7a1783e3,0x7f870bf0,0x8bf6fd6f,
	0x10f00e0,0x26dd59b,0x34c07e87,0x37eb766c,
	0x40d07750,0x90c2b284,0x97d9f870,0x268a57ec,
	0x341f55a5,0x389ac08,0x393ab593,0x393e44c,
	0x480eee90,0x714f88ae,0x818f00e0,0x1199ab13,
	0x55438d4e,0x78249a9c,0x800741d1,0x812911e9,
	0x3057831f,0x8960775a,0x20202020,0x50746547,
	0xa0ae5aed,0xa5bbb78d,0xaab31668,0xac2a4072,
	0xae05593e,0xb45e39c8,0xb5032bb6,0xb16971f4,
	0xbfe10ff8,0xc0a81644,0xc2e6c3ea,0xc77d5f14,
	0xc2824dac,0xcec8154,0xd1b35b00,0xd21cb95e,
	0xd86ccf72,0xd298ab4b,0xd21cb95e,0xd943a47,
	0xdba1f0e,0xdba10c93,0xded64554,0xdf7184db,
	0xe5e48187,0xe4357928,0xeaa9c908,0xeb8b6d50,
	0xeb8d1f90,0xeba1f0e,0xee76b100,0xf63cb5dc,
	0xf610c2e3,0
};



//-1 ����δ֪
//0  ������
//1  �����һ��0x1e8 0x3d34  ��΢�����
//2  ������һ��0x300 0x66e4  ��΢�����
//3  ����0x28����virut����
//4  ����0x2C����virut����
//5  ����0x30����virut����
//6  ����0x1C����virut����
//0x666 ��������Ƕ��ظ�Ⱦ����, ������.
DWORD MatchVirutCE1(BYTE* data)
{
	

	int flag_0x20 = -1, flag2_0x24 = -1, flag3_0x28 = -1;
	int flag_0x2c = -1, flag_0x30 = -1, flag_0x1c = -1;

	for (int i = 0; sig_confirmed_x20[i] != 0; ++i)
	{
		if (*(DWORD*)(data + 0x20) == sig_confirmed_x20[i])
		{
			flag_0x20 = 1;
			break;
		}
	}

	for (int i = 0; sig_denied_0x20[i] != 0; ++i)
	{
		if (*(DWORD*)(data + 0x20) == sig_denied_0x20[i])
		{
			flag_0x20 = 0;
			break;
		}
	}
	

	return -1;
}



int ScanFile(_In_ CHAR* szFileName, _In_ int bScanOnly)
{
	HANDLE hFile = INVALID_HANDLE_VALUE, hFileMapping = INVALID_HANDLE_VALUE;
	int result = 0;
	DWORD dwSizeHigh = 0, dwFileSize = 0;
	BYTE* data = NULL;
	BOOL bFreeFlag = FALSE;
	PIMAGE_DOS_HEADER pidh = NULL;
	PIMAGE_NT_HEADERS pinh = NULL;
	PIMAGE_SECTION_HEADER pish = NULL;
	BOOL AdjustSize = FALSE;
	BOOL isValidSectionTable = FALSE;
	int virutkind = -1;
	int calc_backupvaluemethod = 0;       //1 ����ӷ�  2����xor 3�������
	int oepsearchpos = 0, oepremainbytes = 0;
	BYTE *pcode = NULL;

	//�������
	if (szFileName == NULL || !strcmp(szFileName, ""))
	{
		result = -1;
		goto end1;
	}

	if (bScanOnly)
	{
		hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}
	else
	{
		hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}

	if (hFile == INVALID_HANDLE_VALUE)
	{
		result = -1;
		goto end1;
	}
	
	dwFileSize = GetFileSize(hFile, &dwSizeHigh);

	if (dwFileSize < 0x1000 || dwSizeHigh)
	{
		result = -1;
		goto end2;
	}


	if (bScanOnly)
	{
		hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, NULL, NULL, NULL);
	}
	else
	{
		hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, NULL, NULL, NULL);
	}

	if (hFileMapping == NULL)
	{
		if (bScanOnly == FALSE)
		{
			goto end3;
		}
		DWORD dwTemp = 0;
		data = (BYTE*)malloc(dwFileSize);
		ReadFile(hFile, data, dwFileSize, &dwTemp, NULL);
		bFreeFlag = TRUE;
		if (dwTemp != dwFileSize)
		{
			result = -1;
			goto end3;
		}

		goto new1;
	}

	if (bScanOnly)
	{
		data = (BYTE*)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	}
	else
	{
		data = (BYTE*)MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	}


	if (data == 0)
	{
		result = -1;
		goto end3;
	}

new1:
	pidh = (PIMAGE_DOS_HEADER)data;

	if (pidh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		result = 2;
		goto end4;
	}

	if ((DWORD)pidh->e_lfanew > 0x10000) 
	{
		result = 2;
		goto end4;
	}

	pinh = (PIMAGE_NT_HEADERS)(data + pidh->e_lfanew);

	pish = (PIMAGE_SECTION_HEADER)(pinh + 1);

	if (pinh->Signature != IMAGE_NT_SIGNATURE)
	{
		result = 2;
		goto end4;
	}

	isValidSectionTable = DoSectionCheck(pish,pinh->FileHeader.NumberOfSections);
	if (isValidSectionTable == FALSE)
	{
#if DEBUG
		printf("��Ч�����α�ͷ\n");
#endif // DEBUG

		goto end4;
	}

	//virut.ce,bt   ��������кܶ�΢С�仯�ı���,���Ծͷֿ�����
	//��������û��Ҫ�ֿ�����, ��ȫ������һ��..
	//virutkind == 1, �����Ǿ�һ����, ǰͷ���ִ�СΪ0x1e8, body��С��0x3000~0x4000
	//virutkind == 2, ��������һ����, ǰͷ���ִ�СΪ0x300, body��С��0x6000~0x7000

	virutkind = MatchVirutCE1(data);
	//��һ����, data+20�б�����ͱ��ֵĴ���
	if (virutkind == 1 || virutkind == -1 || virutkind == 2)
	{
#if DEBUG
		if (virutkind == 1)
		{
			printf("ȷ��Ϊ��֪����1, ��ʼ���д���\n");
		}
		if (virutkind == -1)
		{
#if MYTEST
			PIMAGE_SECTION_HEADER pjunk = &pish[pinh->FileHeader.NumberOfSections - 1];
			char tempname[8] = { 0 };
			memcpy(tempname, pjunk->Name, 8);
			
			if (checksecname(tempname))
			{
				if (pjunk->Misc.VirtualSize == 0x1000 && pjunk->Characteristics == 0xc000'0000 && pjunk->SizeOfRawData == 0)
				{
					virutkind = 2;
					printf("����Ϊ��֪����2��4, ��ʼ���д���\n");

					//���޸�PEͷ������. 
					// | xx | 00000   ==>  |xx | yy
					// | xx | kkkk    ==>  |xx|yy|kkkk
					//���ò�Ʋ�����ж�, ���ǲ�����..
					pinh->OptionalHeader.SizeOfImage -= pinh->OptionalHeader.SectionAlignment;
					memset(pjunk, 0, 0x28);
					pinh->FileHeader.NumberOfSections -= 1;

#if DEBUG
					printf("��������������ݳɹ�,SizeOfImage��С%x\n", pinh->OptionalHeader.SectionAlignment);
#endif
					
					//��Ϊrawsize��0, ����ò�Ʋ�����㵽�ļ���С��ȥ, ����Ҳ�����������߼�..
				}
				else
				{
					printf("��θ�Ⱦ����, �޷��޸�, �˳�\n");
					goto end4;
				}
			}
			else
#endif
			{
				printf("δ֪����, ���Դ���\n");
			}


		}	
#endif // DEBUG
		if (bScanOnly)
		{
			result = 3;  //���ֱ���1,δ�ָ�
			goto end4;
		}
		csh handle;
		cs_insn *insn;
		cs_open(CS_ARCH_X86, CS_MODE_32, &handle);


		PIMAGE_SECTION_HEADER pLastSec = &pish[pinh->FileHeader.NumberOfSections - 1];
		DWORD numOfSections = pinh->FileHeader.NumberOfSections;
		DWORD oep = pinh->OptionalHeader.AddressOfEntryPoint;
		PIMAGE_SECTION_HEADER pOepSec = NULL;
		int bNoOEPSecCode = -1;
		DWORD CodeEntry1_RVA = 0;
		DWORD CodeEntry2_RVA = 0;   //β�ڲ�����ڵ�
		DWORD CodeEntry1_Base_RVA = 0; //��ڽڲ����������ַ,�����ַ�Ժ������ȫ������ɾ
		DWORD CodeEntry2_base_RVA = 0; //β�ڲ����������ַ,�����ַ�Ժ������ȫ������ɾ.
		DWORD CodeEntry2_base_RVAAll[10] = { 0 };
		int numofblock2_trueins = 0;
		DWORD CodeEntry2_base_size = 0; //β�ڲ����������ַ��ʼ�Ĳ������С.
		DWORD CodeEntry2_base_sizeAll[10] = { 0 };
		int numofblock1_trueins = 0;
		BOOL hasHook1 = FALSE;
		DWORD hook1pos_RVA = 0;
		DWORD bodybase_RVA = 0;
		

		if (numOfSections == 1)
		{
#if DEBUG
			printf("ֻ��һ������,�˳�\n");
#endif // DEBUG
			goto end4;  //�������������ʱ������. ֱ���˳�.
		}

		//���ж���ڵ��Ƿ������һ������:
		if (oep >= pLastSec->VirtualAddress && oep < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)
		{
#if DEBUG
			printf("��ڵ������һ������\n");
#endif // DEBUG
			bNoOEPSecCode = 1;
			CodeEntry2_RVA = oep;
			goto FuckCode2;
		}

		pOepSec = FindRVASection(pish, numOfSections, oep);

		if (pOepSec == NULL)
		{
#if DEBUG
			printf("�Ҳ�����ڵ������ڵĽ�,�˳�\n");
			goto end4;
#endif
		}

		pcode = data + RVA2FO(pish, numOfSections, oep);
		oepremainbytes = pOepSec->PointerToRawData + pOepSec->SizeOfRawData - RVA2FO(pish, numOfSections, oep);

		if (pOepSec->Misc.VirtualSize == pOepSec->SizeOfRawData)  //���, ��˵���в�����ڽڽ�β��������
		{
#if DEBUG
			printf("��ڽڽ�β�в�������\n");
#endif // DEBUG
			bNoOEPSecCode = FALSE;

			//���ж�OEP�Ƿ�����ڽ�ĩβ-FileAlignment~��ڽ�ĩβλ��, �����, 
			//��ô��˵����ڵ�ֱ�ӱ����õ���ڽڽ�β������ڴ�, �����������HOOK��1����ת���˴�.

			if (pOepSec->VirtualAddress + pOepSec->SizeOfRawData - pinh->OptionalHeader.FileAlignment <= oep &&
				oep <= pOepSec->VirtualAddress + pOepSec->SizeOfRawData)
			{
#if DEBUG
				printf("��ڵ�����ڽڽ�β\n");
#endif // DEBUG
				CodeEntry1_RVA = oep;
				goto FuckCode1;
			}
		}
		hasHook1 = TRUE;

		//����Ӧ�ö��ж�����.. ��ʱһ�ж�Ϊ���ҵ���0x3d34����ʼλ��.
		//���CodeEntry2_RVA����, ��ôֱ�ӽ���β��E9,EB�ҵ����һ�ε�λ��.
		//���CodeEntry1_RVA����, ��ô��Ҫ��ȡoep��β���ܷ�ʽ����Կ, �Լ��õ���ת����β��CodeEntry2RVA
		//������߶�������, ��ô��˵����Hook1��, ��ô��OEP��ʼ��, ��ʼѰ����ת��β�ڻ�����ת������ĩβFileAlignment����E9��ת
		//�ѵ���Ӧ����ת, �Ͱ�Ŀ�ĵص�ֵ��ֵ����Ӧ��CodeEntry����...

		if (CodeEntry1_RVA == 0 && CodeEntry2_RVA == 0)
		{
			//��OEP��ʼ����hook��1
			//HasHook1ΪTRUEʱ�ſ����ߵ����
#if DEBUG
			printf("��ڵ�û������,����hook��1����\n");
#endif // DEBUG
			
			
			
		research_hook1:
			int i;
			CodeEntry1_RVA = 0;
			hasHook1 = TRUE;
			for (i = oepsearchpos; pcode + i < data + pOepSec->PointerToRawData + pOepSec->SizeOfRawData - 0x10;)            //����-0x10Ӱ��Ӧ�ò��Ǻܴ�, ��ҪΪ�˱��������쳣�����
			{
				if (*(pcode + i) == 0xe9)  //����, ֻ��E9
				{
					int jmplen = *(int*)(pcode + i + 1);

					int dest = oep + i + 5 + jmplen;

					//˵��������oep��β
					if (pOepSec->VirtualAddress + pOepSec->SizeOfRawData - pinh->OptionalHeader.FileAlignment <= dest &&
						dest <= pOepSec->VirtualAddress + pOepSec->SizeOfRawData)
					{
						bNoOEPSecCode = 0;
						hook1pos_RVA = oep + i;
						CodeEntry1_RVA = dest;
						oepsearchpos = i + 5; //����������oepblockʧ��, ��ô�ͻ���������������
#if DEBUG
						printf("HOOK��1������OEP��β: hook��1 %x ��ڵ��β%x\n", hook1pos_RVA, dest);
#endif // DEBUG
						break;
					}
						
					
					//˵��������β��
					if (dest >= pLastSec->VirtualAddress && dest < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)
					{
						bNoOEPSecCode = 1;
						hook1pos_RVA = oep + i;
						CodeEntry2_RVA = dest;
#if DEBUG
						printf("HOOK��1������β��: hook��1%x ��β%x\n", hook1pos_RVA, dest);
#endif // DEBUG
						
						break;
					}
				}
				int count = cs_disasm(handle, pcode + i, 0xf, 0, 1, &insn);     //����, ��ʱ���ҵ�ĩβ��ʱ����ܻ���쳣.
				if (count == 1)
				{
					i += insn[0].size;
					cs_free(insn, count);
				}
				else
				{
#if DEBUG
					printf("�����ָ��ʧ��,������ǰ�ֽ�\n");
#endif // DEBUG
					++i;
				}
			}

			if (pcode + i >= data + pOepSec->PointerToRawData + pOepSec->SizeOfRawData - 0x10)
			{
#if DEBUG
				printf("��hook��1λ�ó���\n ���ܲ���virut,������������������޸�,��δ�޸���ȫ,�����жϳ���\n");
#endif // DEBUG
				goto end4;
			}

		}
	FuckCode1:

		//Ȼ���Ƚ���CodeEntry1��
		if (CodeEntry1_RVA)
		{
			if (CodeEntry2_RVA)
			{
				//������, ��ʱ��CodeEntry2_RVAӦ��ҪΪ0;
#if DEBUG
				printf("����codeentry1ʱcodeentry2��0, ������,�˳�\n");
#endif // DEBUG

				goto end4;
			}


			//���������, ���ǿ��ܻ������, Ȼ��������һ����ȫ��������. ��һ�������λ�ÿ�������һ˳��
			BYTE* pcode = data + RVA2FO(pish, numOfSections, CodeEntry1_RVA);
			int jmptimes = 0;
			int prevRVA = CodeEntry1_RVA, nextRVA = 0;
			DWORD block_RVA[5+1] = { 0 };  //β����0��Ϊһ�����
			int block1_confirmed = 0, block2_confirmed, block3_confirmed, block4_confirmed;
			int index = -1;
			int indexAll[10] = { 0 };
			DWORD key1 = 0;
			DWORD key1All[10] = { 0 };
			int method = -1; //1��ʾadd, 0��ʾsub  ��ʼΪ-1,���������������ʱ,ʹ�����
			int methodAll[10] = { -1,-1,-1,-1,-1,-1,-1,-1,-1,-1 };
			int indexAll_Block2[10] = { 0 };
			int decryptsize = 0;  //1, 2, 4.
			while (1)
			{
				block_RVA[jmptimes] = prevRVA;

				for (int i = 0; i < 0x30;)
				{
					if (jmptimes == 0 || jmptimes == 1)
					{
						if (*(pcode + i) >= 0xb8 && *(pcode + i) <= 0xba)
						{
							CodeEntry2_base_size = *(DWORD*)(pcode + i + 1);            //��1de86992_58c��������, ������mov ecx,xxx ��mov edx,yyy����ͬʱ����.. 
							if (CodeEntry2_base_size <= 0x7000 && CodeEntry2_base_size >= 0x3000)
							{							
								CodeEntry2_base_sizeAll[numofblock1_trueins] = *(DWORD*)(pcode + i + 1);
								block1_confirmed = 1;                                        //�и�����.��Ȼ�˴�yyy����0x10000ֱ�ӱ��ų�, ��Ϊ�˱���, �����ü���ͬʱȷ���Ƚϱ���.
																							 //һ�����ȷ���ǵ�һ��ָ���� B8/B9/BA dd_virut_code_length
																							 //�ֱ���mov eax / ecx / edx dd_virut_code_length
								indexAll[numofblock1_trueins] = *(pcode + i) - 0xb8;
								++numofblock1_trueins;
								char regname[3][4] = { "eax","ecx","edx" };
#if DEBUG
								printf("block1����Чָ���ҵ�\n");
								printf("β�ڿ��СΪ%x\n ��ڽ�β����ʹ�õļĴ���Ϊ%s\n", CodeEntry2_base_sizeAll[numofblock1_trueins - 1], regname[numofblock1_trueins - 1]);
#endif // DEBUG
							}
						}

						if (*(pcode + i) == 0x68 && *(pcode + i + 5) == 0xf8 && *(pcode + i + 6) >= 0x58 && *(pcode + i + 6) <= 0x5a)  //push dd ;clc ;pop
						{
							CodeEntry2_base_size = *(DWORD*)(pcode + i + 1);

							if (CodeEntry2_base_size <= 0x8000 && CodeEntry2_base_size >= 0x3000)
							{
								CodeEntry2_base_sizeAll[numofblock1_trueins] = *(DWORD*)(pcode + i + 1);
								
								block1_confirmed = 1;
								indexAll[numofblock1_trueins] = *(pcode + i + 6) - 0x58;
								++numofblock1_trueins;
								char regname[3][4] = { "eax","ecx","edx" };
#if DEBUG
								printf("block1����Чָ���ҵ�\n");
								printf("β�ڿ��СΪ%x\n ��ڽ�β����ʹ�õļĴ���Ϊ%s\n", CodeEntry2_base_sizeAll[numofblock1_trueins - 1], regname[numofblock1_trueins - 1]);
#endif // DEBUG

							}

						}

						if (*(pcode + i) == 0x68 && *(pcode + i + 5) >= 0x58 && *(pcode + i + 5) <= 0x5a)  //push dd pop
						{
							CodeEntry2_base_size = *(DWORD*)(pcode + i + 1);

							if (CodeEntry2_base_size <= 0x8000 && CodeEntry2_base_size >= 0x3000)
							{
								CodeEntry2_base_sizeAll[numofblock1_trueins] = *(DWORD*)(pcode + i + 1);
								
								block1_confirmed = 1;
								indexAll[numofblock1_trueins] = *(pcode + i + 5) - 0x58;
								++numofblock1_trueins;
								char regname[3][4] = { "eax","ecx","edx" };
#if DEBUG
								printf("block1����Чָ���ҵ�\n");
								printf("β�ڿ��СΪ%x\n ��ڽ�β����ʹ�õļĴ���Ϊ%s\n", CodeEntry2_base_sizeAll[numofblock1_trueins - 1], regname[numofblock1_trueins - 1]);
#endif // DEBUG

							}
						}
					}

					if (jmptimes == 1 || jmptimes == 2)
					{
						if (*(pcode + i) == 0x81 && (*(pcode + i + 1) == 0x80 || *(pcode + i + 1) == 0x81 ||
							*(pcode + i + 1) == 0x82 || *(pcode + i + 1) == 0xa8 || *(pcode + i + 1) == 0xa9 || *(pcode + i + 1) == 0xaa))
						{

							if (*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
								*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //�ж�һ�½��ܵĵ�ַ�϶�����β��.
							{
								decryptsize = 4;
								block2_confirmed = 1;
								           
								CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase;
								key1All[numofblock2_trueins] = *(int*)(pcode + i + 6);
								const char *damn = "��֪��";

								if ((*(pcode + i + 1) - 0x80 >= 0) && (*(pcode + i + 1) - 0x80) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0x80;
									methodAll[numofblock2_trueins] = 1;
									damn = "�ӷ�add";
								}
								if ((*(pcode + i + 1) - 0xa8 >= 0) && (*(pcode + i + 1) - 0xa8) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0xa8;
									methodAll[numofblock2_trueins] = 0;
									damn = "����sub";
								}
#if DEBUG
								printf("OEP��β����ʹ�õļ����㷨Ϊ%s, ��ԿΪ%x, ����ַΪ%x\n", damn, key1All[numofblock2_trueins], CodeEntry2_base_RVAAll[numofblock2_trueins]);
#endif // DEBUG
								++numofblock2_trueins;
							}
							
						}

						if (*(pcode + i) == 0x80 && (*(pcode + i + 1) == 0x80 || *(pcode + i + 1) == 0x81 ||
							*(pcode + i + 1) == 0x82 || *(pcode + i + 1) == 0xa8 || *(pcode + i + 1) == 0xa9 || *(pcode + i + 1) == 0xaa))
						{
							if (*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
								*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //�ж�һ�½��ܵĵ�ַ�϶�����β��.
							{
								decryptsize = 1;
								block2_confirmed = 1;
								
								CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase;
								key1All[numofblock2_trueins] = *(BYTE*)(pcode + i + 6);
								const char *damn = "��֪��";

								if ((*(pcode + i + 1) - 0x80 >= 0) && (*(pcode + i + 1) - 0x80) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0x80;
									methodAll[numofblock2_trueins] = 1;
damn = "�ӷ�add";
								}
								if ((*(pcode + i + 1) - 0xa8 >= 0) && (*(pcode + i + 1) - 0xa8) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0xa8;
									methodAll[numofblock2_trueins] = 0;
									damn = "����sub";
								}
#if DEBUG
								printf("OEP��β����ʹ�õļ����㷨Ϊ%s, ��ԿΪ%x, ����ַΪ%x\n", damn, key1All[numofblock2_trueins], CodeEntry2_base_RVAAll[numofblock2_trueins]);
#endif // DEBUG
								++numofblock2_trueins;
							}
						}

						if (*(pcode + i) == 0x66 && *(pcode + i + 1) == 0x81 && (*(pcode + i + 2) == 0x90 || *(pcode + i + 2) == 0x91 ||
							*(pcode + i + 2) == 0x92 || *(pcode + i + 2) == 0x98 || *(pcode + i + 2) == 0x99 || *(pcode + i + 2) == 0x9a))
						{
							if (*(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
								*(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //�ж�һ�½��ܵĵ�ַ�϶�����β��.
							{
								decryptsize = 2;
								block2_confirmed = 1;
								
								CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase;
								key1All[numofblock2_trueins] = *(WORD*)(pcode + i + 7);
								const char *damn = "��֪��";

								if ((*(pcode + i + 2) - 0x90 >= 0) && (*(pcode + i + 2) - 0x90) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0x90;
									methodAll[numofblock2_trueins] = 1;
									damn = "�ӷ�adc";
								}
								if ((*(pcode + i + 2) - 0x98 >= 0) && (*(pcode + i + 2) - 0x98) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0x98;
									methodAll[numofblock2_trueins] = 0;
									damn = "����sbb";
								}
#if DEBUG
								printf("OEP��β����ʹ�õļ����㷨Ϊ%s, ��ԿΪ%x, ����ַΪ%x\n", damn, key1All[numofblock2_trueins], CodeEntry2_base_RVAAll[numofblock2_trueins]);
#endif // DEBUG
								++numofblock2_trueins;

							}
						}

						if (*(pcode + i) == 0x66 && *(pcode + i + 1) == 0x81 && (*(pcode + i + 2) == 0x80 || *(pcode + i + 2) == 0x81 ||
							*(pcode + i + 2) == 0x82 || *(pcode + i + 2) == 0xa8 || *(pcode + i + 2) == 0xa9 || *(pcode + i + 2) == 0xaa))
						{
							if (*(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
								*(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //�ж�һ�½��ܵĵ�ַ�϶�����β��.
							{
								decryptsize = 2;
								block2_confirmed = 1;
								
								CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase;
								key1All[numofblock2_trueins] = *(WORD*)(pcode + i + 7);
								const char *damn = "��֪��";

								if ((*(pcode + i + 2) - 0x80 >= 0) && (*(pcode + i + 2) - 0x80) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0x80;
									methodAll[numofblock2_trueins] = 1;
									damn = "�ӷ�add";
								}
								if ((*(pcode + i + 2) - 0xa8 >= 0) && (*(pcode + i + 2) - 0xa8) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0xa8;
									methodAll[numofblock2_trueins] = 0;
									damn = "����sub";
								}
#if DEBUG
								printf("OEP��β����ʹ�õļ����㷨Ϊ%s, ��ԿΪ%x, ����ַΪ%x\n", damn, key1All[numofblock2_trueins], CodeEntry2_base_RVAAll[numofblock2_trueins]);
#endif // DEBUG
								++numofblock2_trueins;

							}
						}



					}

					if (jmptimes == 2 || jmptimes == 3)
					{
						if (*(pcode + i) == 0x83 && *(pcode + i + 2) == 4 &&
							(*(pcode + i + 1) == 0xe8 || *(pcode + i + 1) == 0xe9 || *(pcode + i + 1) == 0xea))
						{
							index = *(pcode + i + 1) - 0xe8;   //���������ʱ����������ʹ�õļĴ�������.
							block3_confirmed = 1;
						}

						if (*(pcode + i) == 0x83 && *(pcode + i + 2) == 2 &&
							(*(pcode + i + 1) == 0xe8 || *(pcode + i + 1) == 0xe9 || *(pcode + i + 1) == 0xea))
						{
							index = *(pcode + i + 1) - 0xe8;   //���������ʱ����������ʹ�õļĴ�������.
							block3_confirmed = 1;
						}

						if (*(pcode + i) == 0x48 || *(pcode + i + 1) == 0x49 || *(pcode + i + 1) == 0x4a)
						{
							index = *(pcode + i) - 0x48;
							block3_confirmed = 1;
						}

					}

					if (jmptimes == 3 || jmptimes == 4)       //���block4��confirmed�����е㲻�����, �о�����ƺ��б�Ҫ��Щjccȫ����������, ������ͷ�ı�������ʱû������Ҫ��..
					{                                         //���߸ɴ�ȡ����������.
						if (*(pcode + i) == 0x0f && (*(pcode + i + 1) >= 0x80&& *(pcode + i + 1) <= 0x8f))  //��jnb  jge
						{							
							block4_confirmed = 1;
						}
						if (*(pcode + i) >= 0x70 && *(pcode + i) <= 0x7f)   //��jnb jge     //����, ������, �����Ҹ���ȫ������..
						{							
							block4_confirmed = 1;
						}

					}

					if (*(pcode + i) == 0xE9)
					{
						if (jmptimes == 2)  //������==û����, ��Ϊ����һ��һ�����ϼӵ�..����β��������nume8call�Ͳ���.. ����>=
						{
							if (block1_confirmed == 0)
							{
#if DEBUG
								printf("block1����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block1����Чָ��\n");
								
#endif
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
									goto research_hook1;
								}
								printf("���о�������,��virut,�˳�\n");
								goto end4;
							}
						}

						if (jmptimes == 3)
						{
							if (block2_confirmed == 0)
							{
#if DEBUG
								printf("block2����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block2����Чָ��\n");
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
									goto research_hook1;
								}
								printf("���о�������,��virut,�˳�\n");
								goto end4;
								
							}
						}

						if (jmptimes == 4)
						{
							if (block3_confirmed == 0)
							{
#if DEBUG
								printf("block3����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block3����Чָ��\n");
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
									goto research_hook1;
								}
								printf("���о�������,��virut,�˳�\n");
								goto end4;
								
							}
						}
						

						nextRVA = prevRVA + i + 5 + *(int*)(pcode + i + 1);
						if ((nextRVA > pLastSec->VirtualAddress) && (nextRVA < pLastSec->VirtualAddress + pLastSec->SizeOfRawData))  //������ת��β�ڲ������������֮��..
						{
							if (block1_confirmed&&block2_confirmed&&block3_confirmed&&block4_confirmed)
							{
								if (jmptimes == 3 || jmptimes == 4) //���ڿ���, ��ֻ��4���5�����������..
								{
									CodeEntry2_RVA = nextRVA;
#if DEBUG
									printf("β�ڲ���������ڵ�Ϊ%x\n", CodeEntry2_RVA);
#endif // DEBUG
									goto oepvir_decode;
								}
								else
								{
#if DEBUG
									printf("oep�ڽ�β���������������\n");
#endif
									goto end4;
								}
							}
							else
							{
#if DEBUG
								printf("����oep��β����������Чָ��δ�ҵ�\n");
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
									goto research_hook1;
								}
								else
								{
									printf("���о�������,��virut,�˳�\n");
									goto end4;
								}
								goto end4;
							}
							
						}
						break;
					}
					if (*(pcode + i) == 0xeb)
					{
						if (jmptimes == 2)  //������==û����, ��Ϊ����һ��һ�����ϼӵ�..����β��������nume8call�Ͳ���.. ����>=
						{
							if (block1_confirmed == 0)
							{
#if DEBUG
								printf("block1����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block1����Чָ��\n");
#endif
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
									goto research_hook1;
								}
								
								printf("���о�������,��virut,�˳�\n");
								goto end4;
														
							}
						}

						if (jmptimes == 3)
						{
							if (block2_confirmed == 0)
							{
#if DEBUG
								printf("block2����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block2����Чָ��\n");
								
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
									goto research_hook1;
								}
								printf("���о�������,��virut,�˳�\n");
								goto end4;
								
							}
						}

						if (jmptimes == 4)         //�����ʵ�����ܻ��������.. ��Ϊ���һ���ض���E9����.
						{
							if (block3_confirmed == 0)
							{
#if DEBUG
								printf("block3����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block3����Чָ��\n");
								
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
									goto research_hook1;
								}
								printf("���о�������,��virut,�˳�\n");
								goto end4;
								
							}
						}

						nextRVA = prevRVA + i + 2 + *(int8_t*)(pcode + i + 1);
						break;
					}

					int count = cs_disasm(handle, pcode + i, 0xf, 0, 1, &insn);
					if (count == 1)
					{
						i += insn[0].size;
						cs_free(insn, count);
						if (i >= 0x30)
						{
#if DEBUG
							printf("����oep�ڽ�β��ת����\n");
#endif // DEBUG
							if (oepsearchpos < oepremainbytes - 0x10)
							{
								printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
								goto research_hook1;
							}
							printf("���о�������,��virut,�˳�\n");
							goto end4;
						}
					}
					else
					{
#if DEBUG
						printf("����oep�ڽ�β��ת����\n");
#endif // DEBUG

						if (oepsearchpos < oepremainbytes - 0x10)
						{
							printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
							goto research_hook1;
						}
						printf("���о�������,��virut,�˳�\n");
						goto end4;
					}
				}
				pcode = data + RVA2FO(pish, numOfSections, nextRVA);
				prevRVA = nextRVA;
				++jmptimes;

				if (jmptimes >= 5)   //���ֻ������4��, Ȼ�󲻻ᾭ�����
				{
#if DEBUG
					printf("oep��β����������ת��ѭ��, �˳�\n");
#endif

					if (oepsearchpos < oepremainbytes - 0x10)
					{
						printf("������hook��1ѡ��,���ϴ��ѵ�E9��λ�ú����������\n");
						goto research_hook1;
					}
					printf("���о�������,��virut,�˳�\n");
					goto end4;
				}

			}

			
oepvir_decode:

			if (decryptsize == 0)
			{
#if DEBUG
				printf("δ֪���ܷ�ʽ,�˳�\n");
				goto end4;
#endif
			}

			CodeEntry1_Base_RVA = block_RVA[0];
			for (int j = 0; block_RVA[j] != 0; ++j)
			{
				CodeEntry1_Base_RVA = min(CodeEntry1_Base_RVA, block_RVA[j]);     //��ȡ��С��ַ
			}
				

			//��β�����ݽ��лָ�����:
			//������ȷ����ȷ������:
			//����block2�е�����Ϊ��׼, ��Ϊ���ܵ�ָ��Ƚ�׼ȷ.. �����ҹ�������󲿷������ҲӦ��ֻ��һ��..

			if (numofblock2_trueins != 1)
			{
#if DEBUG
				printf("�ж�����Ч�Ӽ�����ָ��,�˳�\n");
#endif
				goto end4;
			}

			for (int m = numofblock1_trueins - 1; m >= 0; --m)
			{
				if (indexAll[m] == indexAll_Block2[0])
				{
					CodeEntry2_base_RVA = CodeEntry2_base_RVAAll[0];
					CodeEntry2_base_size = CodeEntry2_base_sizeAll[m];
					key1 = key1All[0];
					method = methodAll[0];

					if (indexAll[m] == index)  //�ٺ�block3�е�ȷ��һ��
					{
#if DEBUG
						printf("�ٴ�ȷ��block3 index�ɹ�\n");
#endif
					}
				}
			}

			

			DWORD *pTemp = (DWORD*)(data + RVA2FO(pish, numOfSections, CodeEntry2_base_RVA));

			for (int i = 0; i <= CodeEntry2_base_size / decryptsize ;++i)
			{
				if (decryptsize == 1)
				{
					*((BYTE*)pTemp + i) = method ? *((BYTE*)pTemp + i) + LOBYTE(key1) : *((BYTE*)pTemp + i) - LOBYTE(key1);
				}
				if (decryptsize == 2)
				{
					*((WORD*)pTemp + i) = method ? *((WORD*)pTemp + i) + LOWORD(key1) : *((WORD*)pTemp + i) - LOWORD(key1);
				}
				if (decryptsize == 4)
				{
					*((DWORD*)pTemp + i) = method ? *((DWORD*)pTemp + i) + key1 : *((DWORD*)pTemp + i) - key1;
				}
			}

			


			

		}

	FuckCode2:

		if (CodeEntry2_RVA)  //��ʼ����β�ڵ���ת, �ҵ������һ��      //��Щ������ֱ�������β��, ����β����תʱҲ��ȷ����Ч����.
		{
			virutkind = virutkind == -1 ? 1 : virutkind; //�����ֱ������codeentry2������, ��ôĬ����virutkindΪ1, ���ʧ��, �ٽ���virutkindΪ2�Ĵ���
			BYTE *pLastCode = data + RVA2FO(pish, numOfSections, CodeEntry2_RVA);
			DWORD prevRVA = CodeEntry2_RVA;
			DWORD nextRVA = 0;
			int num_e8call = 0;
            int times =  0;
			BOOL findlast = FALSE;
			int backvalue1 = 0, backvalue2 = 0;
			int sig_confirmed1 = 0, sig_confirmed2 = 0;   //4������๻��.
			int sig_confirmed3 = 0, sig_confirmed4 = 0;
			int jmptimes = 0;
			int lastsec_sig_confirmed[10] = { 0 };

refuck:
			pLastCode = data + RVA2FO(pish, numOfSections, CodeEntry2_RVA);
			prevRVA = CodeEntry2_RVA;
			nextRVA = 0;
			num_e8call = 0;
            times = 0;
			findlast = FALSE;
			backvalue1 = 0, backvalue2 = 0;	
            memset(lastsec_sig_confirmed, 0, 10 * 4);
			jmptimes = 0;

			while (1)
			{   
				
				for (int i = 0; i < 0x30 * 0xf; )  //���ݸ���, ���Թ�����.
				{

					for (int j = 0; j < FuckedVirut[virutkind].num_waypoint; ++j)
					{
						if (FuckedVirut[virutkind].mypath[j].nume8call == num_e8call)  //�ҵ���ǰ��e8call
						{
							for (int k = 0; k < FuckedVirut[virutkind].mypath[j].num_confirmed_sig; ++k)
							{
								if (sig_cmp(pLastCode + i, FuckedVirut[virutkind].mypath[j].confirmed_sig[k]))
								{
									lastsec_sig_confirmed[FuckedVirut[virutkind].mypath[j].confirmed_sig_index[k]] = 1;
								}
							}

							if (FuckedVirut[virutkind].mypath[j].times) //����ȷ������Ҫ����ָ������������ָ��.
							{
								for (int k = 0; k < 2; ++k)
								{
									if (sig_cmp(pLastCode + i, FuckedVirut[virutkind].mypath[j].sig[k]))
									{
										++times;
										if (times == FuckedVirut[virutkind].mypath[j].times)
										{
                                         
											if (FuckedVirut[virutkind].mypath[j].size_jmpvalue[k] == 1)  //Ҫô��1, Ҫô��4
											{
												nextRVA = prevRVA + i + FuckedVirut[virutkind].mypath[j].off_jmpvalue[k] + FuckedVirut[virutkind].mypath[j].size_jmpvalue[k]
													+ *(int8_t*)(pLastCode + i + FuckedVirut[virutkind].mypath[j].off_jmpvalue[k]);
                                                goto nextpos;
											}
											nextRVA = prevRVA + i + FuckedVirut[virutkind].mypath[j].off_jmpvalue[k] + FuckedVirut[virutkind].mypath[j].size_jmpvalue[k]
												+ *(int*)(pLastCode + i + FuckedVirut[virutkind].mypath[j].off_jmpvalue[k]);
                                            goto nextpos;
										}
									}
								}

							}


							break;  //ȷ�����˾�ֱ��break; ����Ҫ����ѭ����, ��Ϊnum_e8call��Ψһ��.

						}// end of xxx == nume8call
					}

					if (num_e8call == FuckedVirut[virutkind].lastnume8call && *(pLastCode + i) == 0xc3)
					{
						if (FuckedVirut[virutkind].bHasInstructionBeforeJmpBody == FALSE) //��ʱe9/eb����ֱ�Ӹ��ŵ�
						{
							if (*(pLastCode + i + 5) == 0xeb)
							{
								bodybase_RVA = prevRVA + i + 5 + 2 + *(int8_t*)(pLastCode + i + 5 + 1);  //�����ת��Ŀ�ĵ�ַ
#if DEBUG
								printf("β������block��RVAΪ%x\n", bodybase_RVA);
#endif // DEBUG
								goto outofwhile;
							}

							if (*(pLastCode + i + 5) == 0xe9)
							{
								bodybase_RVA = prevRVA + i + 5 + 5 + *(int*)(pLastCode + i + 5 + 1);
#if DEBUG
								printf("β������block��RVAΪ%x\n", bodybase_RVA);
#endif // DEBUG
								goto outofwhile;
							}
						}
						else
						{
							findlast = TRUE;
							i += 5;
							continue;
						}
					}

					if (FuckedVirut[virutkind].bHasInstructionBeforeJmpBody == TRUE && findlast == TRUE &&
						sig_cmp(pLastCode + i, FuckedVirut[virutkind].LastInstructionBeforeJmpBody))
					{
						//��ʱeb��e9�϶��͸��ŵ�.
						if (*(pLastCode + i + FuckedVirut[virutkind].LastInstructionSize) == 0xeb)
						{
							bodybase_RVA = prevRVA + i + FuckedVirut[virutkind].LastInstructionSize + 2
								+ *(int8_t*)(pLastCode + i + FuckedVirut[virutkind].LastInstructionSize + 1);  //�����ת��Ŀ�ĵ�ַ
#if DEBUG
							printf("β������block��RVAΪ%x\n", bodybase_RVA);
#endif // DEBUG
							goto outofwhile;
						}

						if (*(pLastCode + i + FuckedVirut[virutkind].LastInstructionSize) == 0xe9)
						{
							bodybase_RVA = prevRVA + i + FuckedVirut[virutkind].LastInstructionSize + 5
								+ *(int*)(pLastCode + i + FuckedVirut[virutkind].LastInstructionSize + 1);
#if DEBUG
							printf("β������block��RVAΪ%x\n", bodybase_RVA);
#endif // DEBUG
							goto outofwhile;
						}
					}

					if (sig_cmp(pLastCode + i, "e8"))
					{
						++num_e8call;
                        times = 0; // ����call�Ͱ����������������..
						for (int j = 0; j < FuckedVirut[virutkind].num_waypoint; ++j)
						{
							if (FuckedVirut[virutkind].mypath[j].nume8call == num_e8call)
							{
								//�ȼ���Ƿ����backvalue1�ټ���Ƿ����
								if (FuckedVirut[virutkind].mypath[j].bGenBackValue1)
								{
									backvalue1 = i + 5 + prevRVA + pinh->OptionalHeader.ImageBase;
#if DEBUG
									printf("���ڼ���������ֵ1:%x\n", backvalue1);
#endif
								}

								if (FuckedVirut[virutkind].mypath[j].bFollowIn)
								{
									nextRVA = prevRVA + i + 5 + *(int*)(pLastCode + i + 1);
                                    
                                    goto nextpos;
								}

								break;
							}

						}
					} 

					if (sig_cmp(pLastCode + i, "e9") || sig_cmp(pLastCode + i, "eb"))
					{

						for (int j = 0; j < FuckedVirut[virutkind].num_waypoint; ++j)
						{
							if (num_e8call >= FuckedVirut[virutkind].mypath[j].nume8call + 1)
							{
								//��ʱ����Ҫ��֤��Ӧ��confirmed�Ƿ�Ϊ1
								BOOL bTemp = TRUE;
								for (int m = 0; m < FuckedVirut[virutkind].mypath[j].num_confirmed_sig; ++m)
								{
									if (lastsec_sig_confirmed[FuckedVirut[virutkind].mypath[j].confirmed_sig_index[m]] == FALSE)
									{
										bTemp = FALSE;
									}
								}
								if (bTemp == FALSE)
								{
									if (virutkind < MAXKIND)
									{
#if DEBUG
										printf("�Ǳ���%d,���ַ�ʽ\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
#if DEBUG
									printf("���ܲ���virut����,�˳�\n");
#endif
									goto end4;
								}
							}
							else
							{
								break; //�������С��,��ô������Ҳ�ͻ�С��,��ô��û��Ҫѭ����.
							}
						}



						if (sig_cmp(pLastCode + i, "e9"))
						{
							nextRVA = prevRVA + i + 5 + *(int*)(pLastCode + i + 1);
							break;
						}
						if (sig_cmp(pLastCode + i, "eb"))
						{
							nextRVA = prevRVA + i + 2 + *(int8_t*)(pLastCode + i + 1);
							break;
						}

					} // end of if e9/eb


					int count = cs_disasm(handle, pLastCode + i, 0xf, 0, 1, &insn);
					if (count == 1)
					{
						i += insn[0].size;
						cs_free(insn, count);
						if (i >= 0x100)
						{
							if (virutkind < MAXKIND)
							{
#if DEBUG
								printf("�Ǳ���%d,���ַ�ʽ\n", virutkind);
#endif
								++virutkind;
								goto refuck;
							}
#if DEBUG
							printf("���ܲ���virut����,�˳�\n");
#endif
							goto end4;
						}
					}
					else
					{
						if (virutkind < MAXKIND)
						{
#if DEBUG
							printf("�Ǳ���%d,���ַ�ʽ\n", virutkind);
#endif
							++virutkind;
							goto refuck;
						}
#if DEBUG
						printf("���ܲ���virut����,�˳�\n");
#endif
						goto end4;
					}
				}
nextpos:			
				pLastCode = data + RVA2FO(pish, numOfSections, nextRVA);
				prevRVA = nextRVA;
				++jmptimes;
				if (jmptimes >= 0x100)        //0x100�鹻����..
				{
					if (virutkind < MAXKIND)
					{
#if DEBUG
						printf("��ת��������,������ѭ��,�Ǳ���%d,���ַ�ʽ\n", virutkind);
#endif
						++virutkind;
						goto refuck;
					}
#if DEBUG
					printf("��ת��������,������ѭ��, ���ܲ���virut����,�˳�\n");
#endif
					goto end4;
				}
			}//end of while(1)

		outofwhile:

			// ����bodybase_RVA����, ׼��ȥ����bodybase_RVA+0x53c��������
			//+539 00 c3  ��������������, ���ü����㷨��©�����key, 
			WORD keyfull;
			BYTE* pBlock = data + RVA2FO(pish, numOfSections, bodybase_RVA) + 0;  

            BYTE* db_base_x_after = data + RVA2FO(pish, numOfSections, bodybase_RVA) + FuckedVirut[virutkind].db_before_sig_offset_from_body;

            pBlock = pBlock + FuckedVirut[virutkind].block_descript_offset - 1;
            BOOL found = FALSE;

            for (DWORD i = 0; i <= 0xffff; ++i)   //������DWORD������word��Ϊ�˷�ֹ0ffffִ�к�++i,�ֱ��0, ������ѭ��.
            {
                BYTE db_before[0x10] = { 0 };
                memcpy(db_before, FuckedVirut[virutkind].db_before_sig, FuckedVirut[virutkind].db_before_sig_len);
                int temp = i;

                FuckedVirut[virutkind].EncryptFunc(db_before, i, FuckedVirut[virutkind].dw_key_sig, FuckedVirut[virutkind].db_before_sig_len);

                if (!memcmp(db_base_x_after, db_before, FuckedVirut[virutkind].db_before_sig_len))
                {
                    found = TRUE;
                    //˵���ҵ���
                    keyfull = i;
                    break;
                }
            }

            if (found == FALSE)
            {
#if DEBUG
                printf("������Կ����,�˳�\n");
#endif
                goto end4;
            }

            //Ȼ�����body+ blockƫ�� - 1ʱ��keyfull

            FuckedVirut[virutkind].UpdateKey(&keyfull, FuckedVirut[virutkind].dw_key_sig, FuckedVirut[virutkind].block_descript_offset - 1 - FuckedVirut[virutkind].db_before_sig_offset_from_body);

            //��blockdescript-1��ʼ����

            FuckedVirut[virutkind].DecryptFunc(pBlock, keyfull, FuckedVirut[virutkind].dw_key_sig, FuckedVirut[virutkind].block_descript_size + 1);

			//�������, �ҵ�CodeEntry2_Base_RVA


			//WORD* pBodyBlock = (WORD*)(pBlock + 1 + (*pBlock - 1) * 0x8); //�ҵ�body��block  //���ֽ��ܺ�����blocknum������, �����ֶ�ȥ������..

			WORD *pBodyBlock = NULL;
			for (int i = 0; i < 0x100; ++i)         //������, ��Ϊ��һ���Ŀ������޽϶�
			{
				if (*(WORD*)(pBlock + 1 + i * 8) >= 0x3000 && *(WORD*)(pBlock + 1 + i * 8) <= 0x9000                    //Ϊ��ͨ����
					&& *(WORD*)(pBlock + 1 + i * 8) == (*(WORD*)(pBlock + 1 + 6 + i * 8)&0x7fff))                       //��΢���һ��
				{
					pBodyBlock = (WORD*)(pBlock + 1 + i * 8);    
					break;
				}
			}
			if (pBodyBlock == NULL || *(pBodyBlock + 1) < 0x100)   //body��beforeoffset, Ŀǰ��������: 0x1e8, �� 0x300  ������: ���´�0x2B8..
			{
#if DEBUG
				printf("body��beforeoffset������, ������body�Ľ����㷨����\n");
#endif // DEBUG

				goto end4;
			}

			CodeEntry2_base_RVA = bodybase_RVA - *(pBodyBlock + 2);

			//�����ͨ��������ڵ㷽ʽ�Ļ�, ��ô�Ͳ�����������ָ��... c6 05��c7 05, ����ֻ�е���HOOKʱ��ȥ��������ָ��
			if (hasHook1 == TRUE)
			{
				DWORD CodeToSearch_RVA = 0;
				//������Ѱ�Ұ���before_offset 173��block
				//��һ�����ǰ���before_offset b4��block 
				//���´��ǰ���before_offset c2��block
				//virutkind==4����b5�Ŀ�
				for (int i = 0; i < 0x100; ++i)
				{
					PWORD pTemp = (PWORD)(pBlock + 1 + i * 8);
				
					if ((FuckedVirut[virutkind].recover_off >= *(pTemp + 1)) && (FuckedVirut[virutkind].recover_off < (*(pTemp + 1) + *pTemp)))
					{
						CodeToSearch_RVA = CodeEntry2_base_RVA + *(pTemp + 2);

#if DEBUG
						printf("�����������ָ�ָ��Ĳ��������RVAΪ%x\n", CodeToSearch_RVA);
#endif // DEBUG
						break;
					}
				}

				BYTE *pSearch = data + RVA2FO(pish, numOfSections, CodeToSearch_RVA);
				DWORD Recover1_VA, Recover2_VA;
				BYTE Recover1_Value;
				DWORD Recover2_Value;
				BOOL b1find = FALSE, b2find = FALSE;

				for (int i = 0; i < 0x100; )
				{
					if (*(pSearch + i) == 0xc6 && *(pSearch + i + 1) == 0x05)    //mov <va1>,db
					{
						b1find = TRUE;
						Recover1_VA = *(DWORD*)(pSearch + i + 2);
						Recover1_Value = *(pSearch + i + 6);

#if DEBUG
						printf("��%x���ָ�һ���ֽ�ֵΪ%x\n", Recover1_VA, Recover1_Value);
#endif // DEBUG

						if (b1find&&b2find)
						{
							break;
						}
					}

					if (*(pSearch + i) == 0xc7 && *(pSearch + i + 1) == 0x05)    //mov <va1>,dd
					{
						b2find = TRUE;
						Recover2_VA = *(DWORD*)(pSearch + i + 2);
						Recover2_Value = *(DWORD*)(pSearch + i + 6);

#if DEBUG
						printf("��%x���ָ��ĸ��ֽ�ֵΪ%x\n", Recover2_VA, Recover2_Value);
#endif // DEBUG

						if (b1find && b2find)
						{
							break;
						}
					}

					int count = cs_disasm(handle, pSearch + i, 0xf, 0, 1, &insn);
					if (count == 1)
					{
						i += insn[0].size;
						cs_free(insn, count);
						if (i >= 0x100)
						{
#if DEBUG
							printf("��������movָ��λ�ó���\n");
#endif // DEBUG

							goto end4;
						}
					}
					else
					{
#if DEBUG
						printf("��������movָ��λ�ó���\n");
#endif // DEBUG

						goto end4;
					}
				}

				//�ҵ�������֮��ͰѶ�Ӧλ�õ����ݸ����ָ���

				*(data + RVA2FO(pish, numOfSections, Recover1_VA - pinh->OptionalHeader.ImageBase)) = Recover1_Value;
				*(DWORD*)(data + RVA2FO(pish, numOfSections, Recover2_VA - pinh->OptionalHeader.ImageBase)) = Recover2_Value;
			}


			//��ʱ��ÿ��ǻָ�ԭOEP,��Ϊ���п����ǰ�OEPֱ�����õ�β�ڻ���ڽ�β����������.
			//���Ե�û��hook1��ʱ, ��Ϊû��������c6 05 ; c7 05
			//���Ծ�Ѱ�Ҵ����е�backvalue1, ��backvalue2, Ȼ����ݶ�Ӧ���㷨��������յ�oepֵ.

			if (hasHook1 == FALSE)
			{
				DWORD CodeToSearch_RVA = 0;
					
                //������Ѱ�Ұ���backvalue2ָ���block 
                for (int i = 0; i < 0x100; ++i)
                {
                    PWORD pTemp = (PWORD)(pBlock + 1 + i * 8);

                    if ((FuckedVirut[virutkind].backvalue_off >= *(pTemp + 1)) && (FuckedVirut[virutkind].backvalue_off < (*(pTemp + 1) + *pTemp)))
                    {
                        CodeToSearch_RVA = CodeEntry2_base_RVA + *(pTemp + 2);
#if DEBUG
                        printf("����backvalue2ָ��Ĳ��������RVAΪ%x\n", CodeToSearch_RVA);
#endif // DEBUG
                        break;
                    }
                }
				
				if (CodeToSearch_RVA)
				{
					BYTE *pSearch = data + RVA2FO(pish, numOfSections, CodeToSearch_RVA);
					for (int i = 0; i < 0x100; )
					{  //��Щ���ص�, �÷ֿ�.
						if (virutkind == 3)
						{
							if (sig_cmp(pSearch + i, "81 cd"))   //�����и�81 CD xx xx xx xx   or      ebp, 0FFFFDC91h
							{
								backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
								printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
							}

							if (sig_cmp(pSearch + i, "01 6b f8"))  // add     [ebx-8], ebp  //�ӷ�  //Ŀǰ�Ϳ�������, �����ҾͰ�ʣ�µ�����д��
							{
								calc_backupvaluemethod = 1;
								break;
							}
							if (sig_cmp(pSearch + i, "31 6b f8"))  // xor     [ebx-8], ebp  //���
							{
								calc_backupvaluemethod = 2;
								break;
							}
							if (sig_cmp(pSearch + i, "29 6b f8"))  // sub     [ebx-8], ebp  //����
							{
								calc_backupvaluemethod = 3;
								break;
							}
						}else if (virutkind == 8)
						{
							if (sig_cmp(pSearch + i, "bd"))   //mov ebp, dd_backvalue2
							{
								backvalue2 = *(int*)(pSearch + i + 1);
#if DEBUG
								printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
							}
							if (sig_cmp(pSearch + i, "0f c1 6c 24 20")) //xadd [esp+20],ebp
							{
								calc_backupvaluemethod = 1;
								break;
							}
						}else if (virutkind == 6)
						{
							if (sig_cmp(pSearch + i, "81 f5"))   //xor ebp, dd_backvalue2
							{
								backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
								printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
							}
							if (sig_cmp(pSearch + i, "0f c1 69 fe")) //xadd [ecx-2],ebp
							{
								calc_backupvaluemethod = 1;
								break;
							}
						}else if (virutkind == 9)
						{
                            if (sig_cmp(pSearch + i, "81 f5"))   //xor ebp, dd_backvalue2
                            {
                                backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
                                printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
                            }
                            if (sig_cmp(pSearch + i, "01 2b")) //add [ebx], ebp
                            {
                                calc_backupvaluemethod = 1;
                                break;
                            }
                        }
                        else if (virutkind == 0xa)
                        {
                            if (sig_cmp(pSearch + i, "bd"))   //mov ebp, dd_backvalue2
                            {
                                calc_backupvaluemethod = 1;       //����־�Ȼ���Ǹ�������ȥ��..
                                backvalue2 = *(int*)(pSearch + i + 1);
#if DEBUG
                                printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
                                break;
                            }
                        }
                        else if (virutkind == 0xb || virutkind == 0xc || virutkind == 0xd || virutkind == 0xe)
                        {
                            if (sig_cmp(pSearch + i, "81 ed"))
                            {
                                calc_backupvaluemethod = 1;       
                                backvalue2 = 0 - *(int*)(pSearch + i + 2);
                                backvalue1 = 0;        //������ֺ��Ļ���, ��Ȼ��backvalue1������..
#if DEBUG                       
                                printf("�ر�ı���,���ڼ���������ֵ1:%x\n", backvalue1); //ע��,��һ�б�д��#if DEBUG��������.
                                printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
                                break;
                            }
                        }
						else
						{
							if (sig_cmp(pSearch + i, "81 44 24"))   //add dword ptr [esp+0x24], dd_backvalue2  Ŀǰ�ҾͿ�����һ�ֵ�, ˳��Ѻ����ָ�����..  //���� esp+0x20��. ������ֱ��ȥ��+xx��ƫ��
							{
								calc_backupvaluemethod = 1;
								backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
								printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 74 24"))   //xor dword ptr [esp+0x24], dd_backvalue2
							{
								calc_backupvaluemethod = 2;
								backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
								printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 6c 24"))   //sub dword ptr [esp+0x24], dd_backvalue2
							{
								calc_backupvaluemethod = 3;
								backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
								printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 c5"))  //add ebp, dd_backvalue2    Ŀǰ����4��׼�Ϳ������, ��˳����������ַ�ʽ��д��.
							{
								calc_backupvaluemethod = 1;
								backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
								printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 f5"))  //xor ebp, dd_backvalue2   
							{
								calc_backupvaluemethod = 2;
								backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
								printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 ed"))  //sub ebp, dd_backvalue2   
							{
								calc_backupvaluemethod = 3;
								backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
								printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
								break;
							}
						}
						

						int count = cs_disasm(handle, pSearch + i, 0xf, 0, 1, &insn);
						if (count == 1)
						{
							i += insn[0].size;
							cs_free(insn, count);
							if (i >= 0x100)
							{
#if DEBUG
								printf("��backvalue2ָ��λ�ó���\n");
#endif // DEBUG
								goto end4;
							}
						}
						else
						{
#if DEBUG
							printf("��backvalue2ָ��λ�ó���\n");
#endif // DEBUG
							goto end4;
						}
					}
				}


				//��ʱ��ͨ���������������ԭoepֵ
				//β�ڿ�ʼ����ĵ�e9 xx 00 00 00 00			

				const char *fuck = "god knows";
				if (calc_backupvaluemethod == 1)
				{
					pinh->OptionalHeader.AddressOfEntryPoint = backvalue1 + backvalue2 - pinh->OptionalHeader.ImageBase;
					fuck = "�ӷ�";
				}
				if (calc_backupvaluemethod == 2)
				{
					pinh->OptionalHeader.AddressOfEntryPoint = (backvalue1 ^ backvalue2) - pinh->OptionalHeader.ImageBase;
					fuck = "���";
				}
				if (calc_backupvaluemethod == 3)
				{
					pinh->OptionalHeader.AddressOfEntryPoint = (backvalue1 - backvalue2) - pinh->OptionalHeader.ImageBase;
					fuck = "����";
				}
				

#if DEBUG
				printf("backvalue���㷽��Ϊ:%s\n��������PEͷ�е�OEPΪ%x\n", fuck, pinh->OptionalHeader.AddressOfEntryPoint);
#endif // DEBUG

			}

			//��ʼ�ָ��ڱ�,sizeofimage,�������ļ�ĩβ
			//�Ȼָ�β�ڱ�
			DWORD LastSectionReduce_VSize = pLastSec->Misc.VirtualSize - (CodeEntry2_base_RVA - pLastSec->VirtualAddress);
			DWORD LastSectionReduce_RSize = pLastSec->SizeOfRawData - (RVA2FO(pish, numOfSections, CodeEntry2_base_RVA) - pLastSec->PointerToRawData);
			
#if DEBUG
			printf("��β���ε�VSize��С%x RSize��С%x\n", LastSectionReduce_VSize, LastSectionReduce_RSize);
			printf("��PEͷ��SizeOfImage��С%x ���ļ���С��С%x\n", LastSectionReduce_VSize, LastSectionReduce_RSize);
#endif // DEBUG

			pLastSec->Misc.VirtualSize -= LastSectionReduce_VSize;
			pLastSec->SizeOfRawData -= LastSectionReduce_RSize;
			pinh->OptionalHeader.SizeOfImage -= LastSectionReduce_VSize;

			AdjustSize = TRUE;
			dwFileSize -= LastSectionReduce_RSize;

			//��������������ڽڲ�������
			if (CodeEntry1_RVA)
			{
				DWORD OEPSectionReduce_VSize = pOepSec->Misc.VirtualSize - (CodeEntry1_Base_RVA - pOepSec->VirtualAddress);
				DWORD OEPSectionReduce_RSize = pOepSec->SizeOfRawData - (RVA2FO(pish, numOfSections, CodeEntry1_Base_RVA) - pOepSec->PointerToRawData);


				//������֪, oep����ڱ���Ǽ򵥵ؽ�����: ������������ָ��ָ��vsize+vaddress, Ȼ��vsize = rsize. һ��vsize���϶�filealignȡ�컨�����rsize.
				//����, �ҾͰ��������, �ٰ�vsize��һ�¾�����..
				pOepSec->Misc.VirtualSize -= OEPSectionReduce_VSize;

				if (pOepSec->VirtualAddress + pOepSec->Misc.VirtualSize >= (pOepSec + 1)->VirtualAddress)  //��ζ�Ż��嵽��һ�����ε�����
				{
#if DEBUG
					printf("��ڽڽ�β�������ݸ�������һ����, ���ļ������Ѿ�������\n");
					goto end4;
#endif
				}
				memset((BYTE*)(data + pOepSec->PointerToRawData + pOepSec->Misc.VirtualSize), 0, OEPSectionReduce_VSize);

#if DEBUG
				printf("��OEP���α��VSize��С%x\n", OEPSectionReduce_VSize);
				printf("��OEP���ε�raddr: %x����%x�ֽ���0\n", pOepSec->PointerToRawData + pOepSec->Misc.VirtualSize, OEPSectionReduce_VSize);
#endif // DEBUG


			}

			//�����Ⱦ���
			if (virutkind == 1)
			{
				*(DWORD*)(data + 0x20) = 0;
			}else if (virutkind == 8)
			{
                *(DWORD*)(data + 0x24) = 0;
            }
            else
            {
                pinh->FileHeader.TimeDateStamp = 0;
            }
			
		} // end of if codeentry2

	}

#if DEBUG
	if (virutkind == 0)
	{
		printf("ȷ�Ϸ�virut����,������\n");
	}
#endif // DEBUG

end4:




	if (bFreeFlag)
	{
		free(data);
	}
	else
	{
		UnmapViewOfFile(data);
	}

end3:

	CloseHandle(hFileMapping);


end2:

	if (AdjustSize)
	{
		SetFilePointer(hFile, dwFileSize, NULL, FILE_BEGIN);
		SetEndOfFile(hFile);
	}


	CloseHandle(hFile);

end1:
	return result;

}


int main()
{
    /*char szFile[260] = { "C:\\Users\\bj2017\\OneDrive\\source\\VirutInfectedFileRecovery\\VirutInfectedFileRecovery\\test" };
    ScanFile(szFile, FALSE);*/


    char szFilePath[260] = { "C:\\Users\\bj2017\\OneDrive\\source\\VirutInfectedFileRecovery\\VirutInfectedFileRecovery\\fuckittest" };
    WIN32_FIND_DATA data;
    HANDLE hFind;
    char cFullPath[260];
    char cNewPath[260];
    sprintf_s(cFullPath, "%s\\*.*", szFilePath);
    hFind = FindFirstFile(cFullPath, &data);
    do
    {
        if ((!strcmp(".", data.cFileName)) || (!strcmp("..", data.cFileName)))
        {
            continue;
        }

        sprintf_s(cFullPath, "%s\\%s", szFilePath, data.cFileName);
        printf("�޸��ļ�%s\n", data.cFileName);
        ScanFile(cFullPath, FALSE);
        printf("\n\n");
    } while (FindNextFile(hFind, &data));


	return 0;
}