#include <windows.h>
#include "include/capstone.h"

#pragma comment(lib,"capstone_dll.lib")

#define DEBUG 1

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
//1  ����0x20����virut����
//2  ����0x24����virut����
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
	DWORD dwSizeHigh = 0, dwFileSize;
	BYTE* data = NULL;
	BOOL bFreeFlag = FALSE;
	PIMAGE_DOS_HEADER pidh = NULL;
	PIMAGE_NT_HEADERS pinh = NULL;
	PIMAGE_SECTION_HEADER pish = NULL;
	BOOL AdjustSize = FALSE;
	BOOL isValidSectionTable = FALSE;
	int virutkind = -1;
	int calc_backupvaluemethod = 0;       //1 ����ӷ�  2����xor

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
	
	virutkind = MatchVirutCE1(data);
	//��һ����, data+20�б�����ͱ��ֵĴ���
	if (virutkind == 1 || virutkind == -1)
	{
#if DEBUG
		if (virutkind == 1)
		{
			printf("ȷ��Ϊ��֪����1, ��ʼ���д���\n");
		}
		if (virutkind == -1)
		{
			printf("����Ϊδ֪����, ��ʼ���Դ���\n");
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
			bNoOEPSecCode = TRUE;
			CodeEntry2_RVA = oep;
			goto FuckCode2;
		}

		pOepSec = FindRVASection(pish, numOfSections, oep);
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
			BYTE *pcode = data + RVA2FO(pish, numOfSections, oep);

			int i = 0;
			for (; pcode + i < data + pOepSec->PointerToRawData + pOepSec->SizeOfRawData - 0x10;)            //����-0x10Ӱ��Ӧ�ò��Ǻܴ�, ��ҪΪ�˱��������쳣�����
			{
				if (*(pcode + i) == 0xe9 || *(pcode + i) == 0xe8)  //����, ֻ��E9      //����δ�ҵ�hook�㲹��E8 call����
				{
					int jmplen = *(int*)(pcode + i + 1);

					int dest = oep + i + 5 + jmplen;

					if (bNoOEPSecCode == FALSE)
					{
						//˵��������oep��β
						if (pOepSec->VirtualAddress + pOepSec->SizeOfRawData - pinh->OptionalHeader.FileAlignment <= dest &&
							dest <= pOepSec->VirtualAddress + pOepSec->SizeOfRawData)
						{
							hook1pos_RVA = oep + i;
							CodeEntry1_RVA = dest;
#if DEBUG
							printf("HOOK��1������OEP��β: hook��1 %x ��ڵ��β%x\n", hook1pos_RVA, dest);
#endif // DEBUG
							break;
						}
					}
					//˵��������β��
					if (dest >= pLastSec->VirtualAddress && dest < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)
					{
#if DEBUG
						printf("HOOK��1������β��: hook��1%x ��β%x\n", hook1pos_RVA, dest);
#endif // DEBUG
						hook1pos_RVA = oep + i;
						CodeEntry2_RVA = dest;
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
					printf("��hook��1λ�ó���\n ���ܲ���virut,������������������޸�,��δ�޸���ȫ,�����жϳ���\n");
#endif // DEBUG

					goto end4;
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

			BYTE* pcode1 = data + RVA2FO(pish, numOfSections, CodeEntry1_RVA);
			DWORD block2_RVA, block3_RVA, block4_RVA;
			int block1_confirmed, block2_confirmed, block3_confirmed, block4_confirmed;
			int index = -1;
			int indexAll[10] = { 0 };
			for (int i = 0; i < 0x30;)   //��һ������
			{
				if (*(pcode1 + i) >= 0xb8 && *(pcode1 + i) <= 0xba)
				{
					if (CodeEntry2_base_size <= 0x10000)
					{
						CodeEntry2_base_size = *(DWORD*)(pcode1 + i + 1);            //��1de86992_58c��������, ������mov ecx,xxx ��mov edx,yyy����ͬʱ����.. 
						CodeEntry2_base_sizeAll[numofblock1_trueins] = *(DWORD*)(pcode1 + i + 1);
						block1_confirmed = 1;                                        //�и�����.��Ȼ�˴�yyy����0x10000ֱ�ӱ��ų�, ��Ϊ�˱���, �����ü���ͬʱȷ���Ƚϱ���.
						//һ�����ȷ���ǵ�һ��ָ���� B8/B9/BA dd_virut_code_length
						//�ֱ���mov eax / ecx / edx dd_virut_code_length
						indexAll[numofblock1_trueins] = *(pcode1 + i) - 0xb8;
						++numofblock1_trueins;
						char regname[3][4] = { "eax","edx","ecx" };
#if DEBUG
						printf("block1����Чָ���ҵ�\n");
						printf("β�ڿ��СΪ%x\n ��ڽ�β����ʹ�õļĴ���Ϊ%s\n", CodeEntry2_base_sizeAll[numofblock1_trueins-1], regname[numofblock1_trueins-1]);
#endif // DEBUG
					}
				}
				//eb�Ƚ���������, e9����..  ������п����Ժܴ�, �����һ��ǵ�ȥ�Ҹ��������������, ���ڵõ���ǰָ�봦��ָ���,������û�����..
				//��E9��EBǰ��, �����һЩ
				if (*(pcode1 + i) == 0xE9)
				{

					if (block1_confirmed == 1)
					{
#if DEBUG
						printf("block1����Чָ���ҵ�\n");
#endif // DEBUG
					}
					else
					{
#if DEBUG
						printf("block1����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block1����Чָ��\n");
						printf("���ܲ���virut����,�˳�\n");
#endif
						goto end4;
					}

					block2_RVA = CodeEntry1_RVA + i + 5 + *(int*)(pcode1 + i + 1);
					break;
				}

				if (*(pcode1 + i) == 0xeb)
				{

					if (block1_confirmed == 1)
					{
#if DEBUG
						printf("block1����Чָ���ҵ�\n");
#endif // DEBUG
					}
					else
					{
#if DEBUG
						printf("block1����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block1����Чָ��\n");
						printf("���ܲ���virut����,�˳�\n");
#endif // DEBUG
						goto end4;
					}


					block2_RVA = CodeEntry1_RVA + i + 2 + *(int8_t*)(pcode1 + i + 1);
					break;
				}

				int count = cs_disasm(handle, pcode1 + i, 0xf, 0, 1, &insn);
				if (count == 1)
				{
					i += insn[0].size;
					cs_free(insn, count);
				}
				else
				{
#if DEBUG
					printf("block1����block2λ�ó���\n");
#endif // DEBUG

					goto end4;
				}
			}

			BYTE* pcode2 = data + RVA2FO(pish, numOfSections, block2_RVA);
			DWORD key1 = 0;
			DWORD key1All[10] = { 0 };
			int method = -1; //1��ʾadd, 0��ʾsub  ��ʼΪ-1,���������������ʱ,ʹ�����
			int methodAll[10] = { -1,-1,-1,-1,-1,-1,-1,-1,-1,-1 };
			int indexAll_Block2[10] = { 0 };


			for (int i = 0; i < 0x30;)  //�ڶ�������
			{
				if (*(pcode2 + i) == 0x81 && (*(pcode2 + i + 1) == 0x80 || *(pcode2 + i + 1) == 0x81 ||
					*(pcode2 + i + 1) == 0x82 || *(pcode2 + i + 1) == 0xa8 || *(pcode2 + i + 1) == 0xa9 || *(pcode2 + i + 1) == 0xaa))
				{
					if(*(int*)(pcode2 + i + 2) - pinh->OptionalHeader.ImageBase>=pLastSec->VirtualAddress && 
						*(int*)(pcode2 + i + 2) - pinh->OptionalHeader.ImageBase<pLastSec->VirtualAddress+pLastSec->Misc.VirtualSize)    //�ж�һ�½��ܵĵ�ַ�϶�����β��.

					block2_confirmed = 1;
					CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode2 + i + 2) - pinh->OptionalHeader.ImageBase;
					key1All[numofblock2_trueins] = *(int*)(pcode2 + i + 6);
					const char *damn;

					if ((*(pcode2 + i + 1) - 0x80 >= 0) && (*(pcode2 + i + 1) - 0x80) <= 2)
					{
						indexAll_Block2[numofblock2_trueins] = *(pcode2 + i + 1) - 0x80;
						methodAll[numofblock2_trueins] = 1;
						damn = "�ӷ�";
					}
					if ((*(pcode2 + i + 1) - 0xa8 >= 0) && (*(pcode2 + i + 1) - 0xa8) <= 2)
					{
						indexAll_Block2[numofblock2_trueins] = *(pcode2 + i + 1) - 0xa8;
						methodAll[numofblock2_trueins] = 0;
						damn = "����";
					}

#if DEBUG
					printf("OEP��β����ʹ�õļ����㷨Ϊ%s, ��ԿΪ%x, ����ַΪ%x\n", damn, key1All[numofblock2_trueins],CodeEntry2_base_RVAAll[numofblock2_trueins]);
#endif // DEBUG
					++numofblock2_trueins;

				}
				if (*(pcode2 + i) == 0xE9)
				{

					if (block2_confirmed == 1)
					{
#if DEBUG
						printf("block2����Чָ���ҵ�\n");
#endif // DEBUG
					}
					else
					{
#if DEBUG
						printf("block2����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block2����Чָ��\n");
						printf("���ܲ���virut����,�˳�\n");
#endif // DEBUG
						goto end4;
					}


					block3_RVA = block2_RVA + i + 5 + *(int*)(pcode2 + i + 1);
					break;
				}

				if (*(pcode2 + i) == 0xeb)
				{

					if (block2_confirmed == 1)
					{
#if DEBUG
						printf("block1����Чָ���ҵ�\n");
#endif // DEBUG
					}
					else
					{
#if DEBUG
						printf("block2����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block2����Чָ��\n");
						printf("���ܲ���virut����,�˳�\n");
#endif // DEBUG
						goto end4;
					}


					block3_RVA = block2_RVA + i + 2 + *(int8_t*)(pcode2 + i + 1);
					break;
				}

				int count = cs_disasm(handle, pcode2 + i, 0xf, 0, 1, &insn);
				if (count == 1)
				{
					i += insn[0].size;
					cs_free(insn, count);
				}
				else
				{
#if DEBUG
					printf("��block3λ�ó���\n");
#endif // DEBUG

					goto end4;
				}
			}
			BYTE* pcode3 = data + RVA2FO(pish, numOfSections, block3_RVA);
			for (int i = 0; i < 0x30;)  //����������
			{
				if (*(pcode3 + i) == 0xE9)
				{

					if (block3_confirmed == 1)
					{
#if DEBUG
						printf("block3����Чָ���ҵ�\n");
#endif // DEBUG
					}
					else
					{
#if DEBUG
						printf("block3����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block3����Чָ��\n");
						printf("���ܲ���virut����,�˳�\n");
#endif // DEBUG
						goto end4;
					}


					block4_RVA = block3_RVA + i + 5 + *(int*)(pcode3 + i + 1);
					break;
				}
				if (*(pcode3 + i) == 0xeb)
				{

					if (block3_confirmed == 1)
					{
#if DEBUG
						printf("block3����Чָ���ҵ�\n");
#endif // DEBUG
					}
					else
					{
#if DEBUG
						printf("block3����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block3����Чָ��\n");
						printf("���ܲ���virut����,�˳�\n");
#endif // DEBUG
						goto end4;
					}

					block4_RVA = block3_RVA + i + 2 + *(int8_t*)(pcode3 + i + 1);
					break;
				}

				if (*(pcode3 + i) == 0x83 && *(pcode3 + i + 2) == 4 &&
					(*(pcode3 + i + 1) == 0xe8 || *(pcode3 + i + 1) == 0xe9 || *(pcode3 + i + 1) == 0xea))
				{
					index = *(pcode3 + i + 1) - 0xe8;   //���������ʱ����������ʹ�õļĴ�������.
					block3_confirmed = 1;
				}

				int count = cs_disasm(handle, pcode3 + i, 0xf, 0, 1, &insn);
				if (count == 1)
				{
					i += insn[0].size;
					cs_free(insn, count);
				}
				else
				{
#if DEBUG
					printf("��block4λ�ó���\n");
#endif // DEBUG

					goto end4;
				}
			}

			BYTE* pcode4 = data + RVA2FO(pish, numOfSections, block4_RVA);
			for (int i = 0; i < 0x30;)  //���Ŀ�����
			{
				if (*(pcode4 + i) == 0x0f && *(pcode4 + i + 1) == 0x83)  //��jnb
				{
					block4_confirmed = 1;
				}
				if (*(pcode4 + i) == 0x73)   //��jnb
				{
					block4_confirmed = 1;
				}

				if (*(pcode4 + i) == 0xE9)
				{

					if (block4_confirmed == 1)
					{
#if DEBUG
						printf("block4����Чָ���ҵ�\n");
#endif // DEBUG
					}
					else
					{
#if DEBUG
						printf("block4����Чָ��δ�ҵ�, 0x20�б�ǵ�û�ҵ�block4����Чָ��\n");
						printf("���ܲ���virut����,�˳�\n");
#endif // DEBUG
						goto end4;
					}

					CodeEntry2_RVA = block4_RVA + i + 5 + *(int*)(pcode4 + i + 1);

#if DEBUG
					printf("β�ڲ���������ڵ�Ϊ%x\n", CodeEntry2_RVA);
#endif // DEBUG

					break;
				}
				int count = cs_disasm(handle, pcode4 + i, 0xf, 0, 1, &insn);
				if (count == 1)
				{
					i += insn[0].size;
					cs_free(insn, count);
				}
				else
				{
#if DEBUG
					printf("block4��β�ڲ����������λ�ó���");
#endif // DEBUG

					goto end4;
				}
			}

			CodeEntry1_Base_RVA = min(min(CodeEntry1_RVA, block2_RVA), min(block3_RVA, block4_RVA));  //��ȡ��С��ַ

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
			for (int i = 0; i <= CodeEntry2_base_size / 4; ++i)
			{
				if (method == 1)
				{
					*(pTemp + i) += key1;
				}
				if (method == 0)
				{
					*(pTemp + i) -= key1;
				}
			}

		}

	FuckCode2:

		if (CodeEntry2_RVA)  //��ʼ����β�ڵ���ת, �ҵ������һ��      //��Щ������ֱ�������β��, ����β����תʱҲ��ȷ����Ч����.
		{
			BYTE *pLastCode = data + RVA2FO(pish, numOfSections, CodeEntry2_RVA);
			DWORD prevRVA = CodeEntry2_RVA;
			DWORD nextRVA = 0;
			int num_e8call = 0;
			int times = 0;
			BOOL findlast = FALSE;
			int backvalue1 = 0, backvalue2 = 0;
			int sig_confirmed1 = 0, sig_confirmed2 = 0;   //4������๻��.
			int sig_confirmed3 = 0, sig_confirmed4 = 0;
			int jmptimes = 0;


			while (1)
			{
				for (int i = 0; i < 0x100; )    //ÿһ��һ���3~5��ָ��, ����һЩ��������, ���ݸ���, ������<0x100
				{
					if (*(pLastCode + i) == 0xE8)   //�����Ѿ�������e8 call����, ����λ����������Ӧλ��,     ��Ҫע��call esi��ff d6.. �����Ϊ���������..
					{                               //����1��e8��, ������jz, 0f 84 xx xx xx xx��ֱ������Ŀ��λ��
													//����4��e8��, �����ĵ�һ��jz����, �ڶ���jz, 0f 84 xx xx xx xxҲֱ������Ŀ�ĵ�
													//����8��e8��, �����ĵ�һ��c3��ֱ������5���ֽ�, ���������, ��ʱ�ҵ�lea ecx,[ecx+0] 8d 49 00 + e9/eb xx����, �����jmpĿ�ĵ�ַ����body�Ļ���ַ��!!
						++num_e8call;
						if (num_e8call == 1)  //���ﲻһ����E8 00 00 00 00, ����ûʲôӰ��.
						{
							backvalue1 = i + 5 + prevRVA + pinh->OptionalHeader.ImageBase;
#if DEBUG
							printf("���ڼ���������ֵ1:%x\n", backvalue1);
#endif
							//��һ��callҲҪ��, �Ժ��callȫ������
							nextRVA = prevRVA + i + 5 + *(int*)(pLastCode + i + 1);
							if ((nextRVA > pLastSec->VirtualAddress) && (nextRVA < pLastSec->VirtualAddress + pLastSec->SizeOfRawData))
							{

								break;  //����������ʱ���break; �����������ľ͵�û��������
							}
						}

					}

					if (num_e8call == 1)  //8B 6C 24 20  mov     ebp, [esp+0x20] ;
					{
						if (*(DWORD*)(pLastCode + i) == 0x20246c8b)
						{
							sig_confirmed1 = 1;
						}

						if (*(pLastCode + i) == 0x81 && *(pLastCode + i + 1) == 0x44
							&& *(pLastCode + i + 2) == 0x24 && *(pLastCode + i + 3) == 0x20)
						{
							sig_confirmed2 = 1;
							backvalue2 = *(int*)(pLastCode + i + 4);
							calc_backupvaluemethod = 1;
#if DEBUG
							printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
						}

						if (*(pLastCode + i) == 0x81 && *(pLastCode + i + 1) == 0x74
							&& *(pLastCode + i + 2) == 0x24 && *(pLastCode + i + 3) == 0x20)
						{
							sig_confirmed2 = 1;
							backvalue2 = *(int*)(pLastCode + i + 4);
							calc_backupvaluemethod = 2;
#if DEBUG
							printf("���ڼ���������ֵ2:%x\n", backvalue2);
#endif
						}

						if (*(pLastCode + i) == 0x0f && *(pLastCode + i + 1) == 0x84)  //jz pe_find ֱ����
						{
							nextRVA = prevRVA + i + 6 + *(int*)(pLastCode + i + 2);
							break;
						}
						
					}

					if (num_e8call == 4)
					{
						if (*(pLastCode + i) == 0x66 && *(pLastCode + i + 1) == 0x8c && *(pLastCode + i + 2) == 0xc8)   //mov ax, cs
						{
							sig_confirmed3 = 1;
						}

						if (*(DWORD*)(pLastCode + i) == 0x05e8c166)      //shr ax,5
						{
							sig_confirmed4 = 1;
						}

						if (*(pLastCode + i) == 0x0f && *(pLastCode + i + 1) == 0x84)
						{
							++times;
							if (times == 2)  //�ڶ���jz
							{
								nextRVA = prevRVA + i + 6 + *(int*)(pLastCode + i + 2);
								break;
							}
						}
					}

					if (num_e8call == 8 && *(pLastCode + i) == 0xc3)
					{
						i += 5;
						findlast = TRUE;
						continue;
					}
					if (findlast && *(pLastCode + i) == 0x8d && *(pLastCode + i + 1) == 0x49 && *(pLastCode + i + 2) == 0x00) //lea ecx, [ecx+0]
					{
						//��ʱeb��e9�϶��͸��ŵ�.
						if (*(pLastCode + i + 3) == 0xeb)
						{
							bodybase_RVA = prevRVA + i + 3 + 2 + *(int8_t*)(pLastCode + i + 3 + 1);  //�����ת��Ŀ�ĵ�ַ
#if DEBUG
							printf("β������block��RVAΪ%x\n",bodybase_RVA);
#endif // DEBUG
							goto outofwhile;
						}

						if (*(pLastCode + i + 3) == 0xe9)
						{
							bodybase_RVA = prevRVA + i + 3 + 5 + *(int*)(pLastCode + i + 3 + 1);
#if DEBUG
							printf("β������block��RVAΪ%x\n", bodybase_RVA);
#endif // DEBUG
							goto outofwhile;
						}

					}

					//��E9��EBǰ��,��������һЩ.
					if (*(pLastCode + i) == 0xE9)
					{
						if (num_e8call >= 2)
						{
							if (sig_confirmed1 == 1 && sig_confirmed2 == 1)
							{
#if DEBUG
								;   //�ǵĻ�ʲô������, ���ǵĻ��͵��˳���.
#endif
							}
							else
							{
#if DEBUG
								printf("���ܲ���virut����,�˳�\n");
#endif
								goto end4;
							}
						}

						if (num_e8call >= 5)
						{
							if (sig_confirmed3 == 1 && sig_confirmed4 == 1)
							{
#if DEBUG
								;   //�ǵĻ�ʲô������, ���ǵĻ��͵��˳���.
#endif
							}
							else
							{
#if DEBUG
								printf("���ܲ���virut����,�˳�\n");
#endif
								goto end4;
							}
						}

						nextRVA = prevRVA + i + 5 + *(int*)(pLastCode + i + 1);
						if ((nextRVA > pLastSec->VirtualAddress) && (nextRVA < pLastSec->VirtualAddress + pLastSec->SizeOfRawData))
						{

							break;  //����������ʱ���break; �����������ľ͵�û��������
						}
					}
					if (*(pLastCode + i) == 0xeb)
					{
						if (num_e8call >= 2)
						{
							if (sig_confirmed1 == 1 && sig_confirmed2 == 1)
							{
#if DEBUG
								;   //�ǵĻ�ʲô������, ���ǵĻ��͵��˳���.
#endif
							}
							else
							{
#if DEBUG
								printf("���ܲ���virut����,�˳�\n");
#endif
								goto end4;
							}
						}

						if (num_e8call >= 5)
						{
							if (sig_confirmed3 == 1 && sig_confirmed4 == 1)
							{
#if DEBUG
								;   //�ǵĻ�ʲô������, ���ǵĻ��͵��˳���.
#endif
							}
							else
							{
#if DEBUG
								printf("���ܲ���virut����,�˳�\n");
#endif
								goto end4;
							}
						}

						nextRVA = prevRVA + i + 2 + *(int8_t*)(pLastCode + i + 1);
						break;
					}

					int count = cs_disasm(handle, pLastCode + i, 0xf, 0, 1, &insn);
					if (count == 1)
					{
						i += insn[0].size;
						cs_free(insn, count);
						if (i >= 0x100)
						{
#if DEBUG
							printf("��β��0x3d34��bodyλ�ó���\n");
#endif // DEBUG

							goto end4;
						}
					}
					else
					{
#if DEBUG
						printf("��β��0x3d34��bodyλ�ó���\n");
#endif // DEBUG

						goto end4;
					}
				}
				pLastCode = data + RVA2FO(pish, numOfSections, nextRVA);
				prevRVA = nextRVA;
				++jmptimes;
				if (jmptimes >= 0x100)
				{
#if DEBUG
					printf("��ת��������,���ܳ�����ѭ��,��������virut\n");
#endif 
					goto end4;
				}
			}//end of while(1)

		outofwhile:

			// ����bodybase_RVA����, ׼��ȥ����bodybase_RVA+0x53c��������
			//+539 00 c3  ��������������, ���ü����㷨��©�����key, 

			;
			BYTE db_base_minus3_before = 0x00, db_base_minus3_after;
			BYTE db_base_minus2_before = 0xc3, db_base_minus2_after;
			BYTE key1, key2;
			WORD keyfull;
			BYTE* pBlock = data + RVA2FO(pish, numOfSections, bodybase_RVA) + 0x53b;  //ָ�����block�ṹ������ǰ��blocknum

			db_base_minus3_after = *(data + RVA2FO(pish, numOfSections, bodybase_RVA) + 0x53c - 3);
			db_base_minus2_after = *(data + RVA2FO(pish, numOfSections, bodybase_RVA) + 0x53c - 2);

			key1 = db_base_minus3_after ^ db_base_minus3_before;
			key2 = db_base_minus2_after ^ db_base_minus2_before;


			key1 *= 0xd;
			keyfull = ((WORD)key1 << 8) | key2;

			//Ȼ����ܸ�0x70 * 8�ֽ��� , ��Ϊ�����0x64������..
			for (int i=0; i < 0x70 * 8; ++i)
			{
				keyfull *= 0xd;
				keyfull = HIBYTE(keyfull) | (LOBYTE(keyfull) << 8); //xchg dh,dl
				*(pBlock + i) ^= LOBYTE(keyfull);         //ע��,���Ե�ʱ��,ÿ�ζ���ı��ļ�������,����Ҫÿ�α���ԭ���ļ�, �����ٸı�һ��, �ͱ����ԭ����.
			}

			//�������, �ҵ�CodeEntry2_Base_RVA


			//WORD* pBodyBlock = (WORD*)(pBlock + 1 + (*pBlock - 1) * 0x8); //�ҵ�body��block  //���ֽ��ܺ�����blocknum������, �����ֶ�ȥ������..

			WORD *pBodyBlock = NULL;
			for (int i = 0; i < 0x70; ++i)
			{
				if (*(WORD*)(pBlock + 1 + i * 8) == 0x3d34 || *(WORD*)(pBlock + 1 + i * 8) == 0x3eb0
					|| *(WORD*)(pBlock + 1 + i * 8) == 0x3ebc)
				{
					pBodyBlock = (WORD*)(pBlock + 1 + i * 8);    
					break;
				}
			}
			if (pBodyBlock == NULL || *(pBodyBlock + 1) != 0x1e8)
			{
#if DEBUG
				printf("Ѱ��body��block����\n");
#endif // DEBUG

				goto end4;
			}

			CodeEntry2_base_RVA = bodybase_RVA - *(pBodyBlock + 2);

			//��Ϊ�ҷ���, �����ͨ��������ڵ㷽ʽ�Ļ�, ��ô�Ͳ�����������ָ��...
			if (hasHook1 == TRUE)
			{
				DWORD CodeToSearch_RVA = 0;
				//������Ѱ�Ұ���before_offset 173��block
				for (int i = 0; i < 0x70; ++i)
				{
					PWORD pTemp = (PWORD)(pBlock + 1 + i * 8);
					if ((0x173 >= *(pTemp + 1)) && (0x173 < (*(pTemp + 1) + *pTemp)))
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
			//���Ե�û��hook1��ʱ, �Ͱ�OEP����ΪRecover1_VA-Imagebase��Recover2_VA-ImageBase�н�С����һ��

			if (hasHook1 == FALSE)
			{
				//��ʱ��ͨ���������������ԭoepֵ
				//β�ڿ�ʼ����ĵ�e9 xx 00 00 00 00			

				if (calc_backupvaluemethod == 1)
				{
					pinh->OptionalHeader.AddressOfEntryPoint = backvalue1 + backvalue2 - pinh->OptionalHeader.ImageBase;
				}
				if (calc_backupvaluemethod == 2)
				{
					pinh->OptionalHeader.AddressOfEntryPoint = (backvalue1 ^ backvalue2) - pinh->OptionalHeader.ImageBase;
				}
				

#if DEBUG
				printf("��������PEͷ�е�OEPΪ%x\n", pinh->OptionalHeader.AddressOfEntryPoint);
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
					printf("��ڽڽ�β�������ݸ�������һ����, ���ļ��Ѿ�������\n");
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
			*(DWORD*)(data + 0x20) = 0;

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
	/*char szFile[260] = { "C:\\Users\\bj2017\\Documents\\VirutInfectedFileRecovery\\VirutInfectedFileRecovery\\VirutInfectedFileRecovery\\test" };
	ScanFile(szFile, FALSE);*/


	char szFilePath[260] = { "C:\\Users\\bj2017\\Documents\\VirutInfectedFileRecovery\\VirutInfectedFileRecovery\\VirutInfectedFileRecovery\\fuckittest" };
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
	  // MessageBox(NULL,data.cFileName,"Look",0);
	  sprintf_s(cFullPath, "%s\\%s", szFilePath, data.cFileName);
	  printf("�޸��ļ�%s\n", data.cFileName);
	  ScanFile(cFullPath,FALSE);
	  printf("\n\n");
	} while (FindNextFile(hFind, &data));


	return 0;
}