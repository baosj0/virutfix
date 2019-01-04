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
		return 0;  //没找到
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
		return 0;  //没找到
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



//-1 代表未知
//0  代表不是
//1  代表0x20大类virut变种
//2  代表0x24大类virut变种
//3  代表0x28大类virut变种
//4  代表0x2C大类virut变种
//5  代表0x30大类virut变种
//6  代表0x1C大类virut变种
//0x666 代表可能是多重感染变种, 不处理.
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
	int calc_backupvaluemethod = 0;       //1 代表加法  2代表xor 3代表减法
	int oepsearchpos = 0, oepremainbytes = 0;
	BYTE *pcode = NULL;

	//参数检查
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
		printf("无效的区段表头\n");
#endif // DEBUG

		goto end4;
	}

	//virut.ce,bt   由于这个有很多微小变化的变种,所以就分开处理
	//后来发现没必要分开处理, 就全部合在一起..
	//virutkind == 1, 代表是旧一代的, 前头部分大小为0x1e8, body大小在0x3000~0x4000
	//virutkind == 2, 代表是新一代的, 前头部分大小为0x300, body大小在0x6000~0x7000

	virutkind = MatchVirutCE1(data);
	//第一大类, data+20有标记类型变种的处理
	if (virutkind == 1 || virutkind == -1 || virutkind == 2)
	{
#if DEBUG
		if (virutkind == 1)
		{
			printf("确认为已知变种1, 开始进行处理\n");
		}
		if (virutkind == -1)
		{
			printf("可能为未知变种, 开始尝试处理\n");
		}	
#endif // DEBUG
		if (bScanOnly)
		{
			result = 3;  //发现变种1,未恢复
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
		DWORD CodeEntry2_RVA = 0;   //尾节病毒入口点
		DWORD CodeEntry1_Base_RVA = 0; //入口节病毒代码基地址,这个地址以后的数据全部可以删
		DWORD CodeEntry2_base_RVA = 0; //尾节病毒代码基地址,这个地址以后的数据全部可以删.
		DWORD CodeEntry2_base_RVAAll[10] = { 0 };
		int numofblock2_trueins = 0;
		DWORD CodeEntry2_base_size = 0; //尾节病毒代码基地址开始的病毒块大小.
		DWORD CodeEntry2_base_sizeAll[10] = { 0 };
		int numofblock1_trueins = 0;
		BOOL hasHook1 = FALSE;
		DWORD hook1pos_RVA = 0;
		DWORD bodybase_RVA = 0;
		

		if (numOfSections == 1)
		{
#if DEBUG
			printf("只有一个区段,退出\n");
#endif // DEBUG
			goto end4;  //这种特殊情况暂时不考虑. 直接退出.
		}

		//先判断入口点是否在最后一个区段:
		if (oep >= pLastSec->VirtualAddress && oep < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)
		{
#if DEBUG
			printf("入口点在最后一个区段\n");
#endif // DEBUG
			bNoOEPSecCode = TRUE;
			CodeEntry2_RVA = oep;
			goto FuckCode2;
		}

		pOepSec = FindRVASection(pish, numOfSections, oep);
		pcode = data + RVA2FO(pish, numOfSections, oep);
		oepremainbytes = pOepSec->PointerToRawData + pOepSec->SizeOfRawData - RVA2FO(pish, numOfSections, oep);

		if (pOepSec->Misc.VirtualSize == pOepSec->SizeOfRawData)  //相等, 则说明有插入入口节节尾病毒代码
		{
#if DEBUG
			printf("入口节节尾有病毒代码\n");
#endif // DEBUG
			bNoOEPSecCode = FALSE;

			//再判断OEP是否在入口节末尾-FileAlignment~入口节末尾位置, 如果是, 
			//那么就说明入口点直接被设置到入口节节尾病毒入口处, 否则就是利用HOOK点1来跳转到此处.

			if (pOepSec->VirtualAddress + pOepSec->SizeOfRawData - pinh->OptionalHeader.FileAlignment <= oep &&
				oep <= pOepSec->VirtualAddress + pOepSec->SizeOfRawData)
			{
#if DEBUG
				printf("入口点在入口节节尾\n");
#endif // DEBUG
				CodeEntry1_RVA = oep;
				goto FuckCode1;
			}
		}
		hasHook1 = TRUE;

		//条件应该都判断完了.. 此时一切都为了找到那0x3d34的起始位置.
		//如果CodeEntry2_RVA存在, 那么直接解析尾节E9,EB找到最后一段的位置.
		//如果CodeEntry1_RVA存在, 那么就要提取oep节尾加密方式和密钥, 以及得到跳转到的尾节CodeEntry2RVA
		//如果两者都不存在, 那么就说明有Hook1点, 那么从OEP开始处, 开始寻找跳转到尾节或者跳转到本节末尾FileAlignment处的E9跳转
		//搜到对应的跳转, 就把目的地的值赋值给对应的CodeEntry变量...

		if (CodeEntry1_RVA == 0 && CodeEntry2_RVA == 0)
		{
			//从OEP开始搜索hook点1
			//HasHook1为TRUE时才可能走到这儿
#if DEBUG
			printf("入口点没被更改,进行hook点1搜索\n");
#endif // DEBUG
			
			
			
		research_hook1:
			int i;
			CodeEntry1_RVA = 0;
			hasHook1 = TRUE;
			for (i = oepsearchpos; pcode + i < data + pOepSec->PointerToRawData + pOepSec->SizeOfRawData - 0x10;)            //这里-0x10影响应该不是很大, 主要为了避免后面出异常的情况
			{
				if (*(pcode + i) == 0xe9)  //这里, 只有E9
				{
					int jmplen = *(int*)(pcode + i + 1);

					int dest = oep + i + 5 + jmplen;

					if (bNoOEPSecCode == FALSE)
					{
						//说明跳到了oep节尾
						if (pOepSec->VirtualAddress + pOepSec->SizeOfRawData - pinh->OptionalHeader.FileAlignment <= dest &&
							dest <= pOepSec->VirtualAddress + pOepSec->SizeOfRawData)
						{
							hook1pos_RVA = oep + i;
							CodeEntry1_RVA = dest;
							oepsearchpos = i + 5; //如果后面解析oepblock失败, 那么就会跳回来继续搜索
#if DEBUG
							printf("HOOK点1跳到了OEP节尾: hook点1 %x 入口点节尾%x\n", hook1pos_RVA, dest);
#endif // DEBUG
							break;
						}
					}
					//说明跳到了尾节
					if (dest >= pLastSec->VirtualAddress && dest < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)
					{
						hook1pos_RVA = oep + i;
						CodeEntry2_RVA = dest;
#if DEBUG
						printf("HOOK点1跳到了尾节: hook点1%x 节尾%x\n", hook1pos_RVA, dest);
#endif // DEBUG
						
						break;
					}
				}
				int count = cs_disasm(handle, pcode + i, 0xf, 0, 1, &insn);     //这里, 有时候找到末尾的时候可能会出异常.
				if (count == 1)
				{
					i += insn[0].size;
					cs_free(insn, count);
				}
				else
				{
#if DEBUG
					printf("反汇编指令失败,跳过当前字节\n");
#endif // DEBUG
					++i;
				}
			}

			if (pcode + i >= data + pOepSec->PointerToRawData + pOepSec->SizeOfRawData - 0x10)
			{
#if DEBUG
				printf("找hook点1位置出错\n 可能不是virut,或该样本曾经被部分修复,但未修复完全,导致判断出错\n");
#endif // DEBUG
				goto end4;
			}

		}
	FuckCode1:

		//然后先解析CodeEntry1的
		if (CodeEntry1_RVA)
		{
			if (CodeEntry2_RVA)
			{
				//不正常, 此时的CodeEntry2_RVA应该要为0;
#if DEBUG
				printf("解析codeentry1时codeentry2非0, 不正常,退出\n");
#endif // DEBUG

				goto end4;
			}


			//新增的情况, 就是可能会有五块, 然后其中有一块是全垃圾代码. 这一垃圾块的位置可能是任一顺序
			BYTE* pcode = data + RVA2FO(pish, numOfSections, CodeEntry1_RVA);
			int jmptimes = 0;
			int prevRVA = CodeEntry1_RVA, nextRVA = 0;
			DWORD block_RVA[5] = { 0 };
			int block1_confirmed, block2_confirmed, block3_confirmed, block4_confirmed;
			int index = -1;
			int indexAll[10] = { 0 };
			DWORD key1 = 0;
			DWORD key1All[10] = { 0 };
			int method = -1; //1表示add, 0表示sub  初始为-1,这样出现意外情况时,使其出错
			int methodAll[10] = { -1,-1,-1,-1,-1,-1,-1,-1,-1,-1 };
			int indexAll_Block2[10] = { 0 };

			while (1)
			{
				block_RVA[jmptimes] = prevRVA;

				for (int i = 0; i < 0x30;)
				{
					if (jmptimes == 0 || jmptimes == 1)
					{
						if (*(pcode + i) >= 0xb8 && *(pcode + i) <= 0xba)
						{
							CodeEntry2_base_size = *(DWORD*)(pcode + i + 1);            //在1de86992_58c的样本中, 发现有mov ecx,xxx 和mov edx,yyy两个同时出现.. 
							if (CodeEntry2_base_size <= 0x7000 && CodeEntry2_base_size >= 0x3000)
							{							
								CodeEntry2_base_sizeAll[numofblock1_trueins] = *(DWORD*)(pcode + i + 1);
								block1_confirmed = 1;                                        //有干扰项.虽然此处yyy大于0x10000直接被排除, 但为了保险, 还是用几块同时确定比较保险.
																							 //一般可以确认是第一条指令了 B8/B9/BA dd_virut_code_length
																							 //分别是mov eax / ecx / edx dd_virut_code_length
								indexAll[numofblock1_trueins] = *(pcode + i) - 0xb8;
								++numofblock1_trueins;
								char regname[3][4] = { "eax","ecx","edx" };
#if DEBUG
								printf("block1中有效指令找到\n");
								printf("尾节块大小为%x\n 入口节尾病毒使用的寄存器为%s\n", CodeEntry2_base_sizeAll[numofblock1_trueins - 1], regname[numofblock1_trueins - 1]);
#endif // DEBUG
							}
						}

						if (*(pcode + i) == 0x68 && *(pcode + i + 5) == 0xf8 && *(pcode + i + 6) >= 0x58 && *(pcode + i + 6) <= 0x5a)
						{
							CodeEntry2_base_size = *(DWORD*)(pcode + i + 1);

							if (CodeEntry2_base_size <= 0x8000 && CodeEntry2_base_size >= 0x3000)
							{
								CodeEntry2_base_sizeAll[numofblock1_trueins] = *(DWORD*)(pcode + i + 1);
								virutkind = 2;
								block1_confirmed = 1;
								indexAll[numofblock1_trueins] = *(pcode + i + 6) - 0x58;
								++numofblock1_trueins;
								char regname[3][4] = { "eax","ecx","edx" };
#if DEBUG
								printf("block1中有效指令找到\n");
								printf("尾节块大小为%x\n 入口节尾病毒使用的寄存器为%s\n", CodeEntry2_base_sizeAll[numofblock1_trueins - 1], regname[numofblock1_trueins - 1]);
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
								*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //判断一下解密的地址肯定是在尾节.
							{
								block2_confirmed = 1;
								virutkind = 1;           //可以确认是旧一代
								CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase;
								key1All[numofblock2_trueins] = *(int*)(pcode + i + 6);
								const char *damn = "不知道";

								if ((*(pcode + i + 1) - 0x80 >= 0) && (*(pcode + i + 1) - 0x80) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0x80;
									methodAll[numofblock2_trueins] = 1;
									damn = "加法add";
								}
								if ((*(pcode + i + 1) - 0xa8 >= 0) && (*(pcode + i + 1) - 0xa8) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0xa8;
									methodAll[numofblock2_trueins] = 0;
									damn = "减法sub";
								}
#if DEBUG
								printf("OEP节尾病毒使用的加密算法为%s, 密钥为%x, 基地址为%x\n", damn, key1All[numofblock2_trueins], CodeEntry2_base_RVAAll[numofblock2_trueins]);
#endif // DEBUG
								++numofblock2_trueins;
							}
							
						}

						if (*(pcode + i) == 0x66 && *(pcode + i + 1) == 0x81 && (*(pcode + i + 2) == 0x90 || *(pcode + i + 2) == 0x91 ||
							*(pcode + i + 2) == 0x92 || *(pcode + i + 2) == 0x98 || *(pcode + i + 2) == 0x99 || *(pcode + i + 2) == 0x9a))
						{
							if (*(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
								*(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //判断一下解密的地址肯定是在尾节.
							{
								block2_confirmed = 1;
								virutkind = 2;  //可以确认是新一代
								CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase;
								key1All[numofblock2_trueins] = *(WORD*)(pcode + i + 7);
								const char *damn = "不知道";

								if ((*(pcode + i + 2) - 0x90 >= 0) && (*(pcode + i + 2) - 0x90) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0x90;
									methodAll[numofblock2_trueins] = 1;
									damn = "加法adc";
								}
								if ((*(pcode + i + 2) - 0x98 >= 0) && (*(pcode + i + 2) - 0x98) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0x98;
									methodAll[numofblock2_trueins] = 0;
									damn = "减法sbb";
								}
#if DEBUG
								printf("OEP节尾病毒使用的加密算法为%s, 密钥为%x, 基地址为%x\n", damn, key1All[numofblock2_trueins], CodeEntry2_base_RVAAll[numofblock2_trueins]);
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
							index = *(pcode + i + 1) - 0xe8;   //这个用于临时保存第三块的使用的寄存器索引.
							block3_confirmed = 1;
						}

						if (*(pcode + i) == 0x83 && *(pcode + i + 2) == 2 &&
							(*(pcode + i + 1) == 0xe8 || *(pcode + i + 1) == 0xe9 || *(pcode + i + 1) == 0xea))
						{
							index = *(pcode + i + 1) - 0xe8;   //这个用于临时保存第三块的使用的寄存器索引.
							block3_confirmed = 1;
						}

					}

					if (jmptimes == 3 || jmptimes == 4)       //这个block4的confirmed让人有点不大放心, 感觉这个似乎有必要那些jcc全部给他加上, 不过手头的变种又暂时没发现需要的..
					{                                         //或者干脆取消它就完了.
						if (*(pcode + i) == 0x0f && (*(pcode + i + 1) == 0x83|| *(pcode + i + 1) == 0x8d))  //长jnb  jge
						{							
							block4_confirmed = 1;
						}
						if (*(pcode + i) == 0x73 || *(pcode + i) == 0x7d)   //短jnb jge
						{							
							block4_confirmed = 1;
						}

					}

					if (*(pcode + i) == 0xE9)
					{
						if (jmptimes == 2)  //这里用==没问题, 因为都是一次一次往上加的..后面尾部解析的nume8call就不行.. 得用>=
						{
							if (block1_confirmed == 0)
							{
#if DEBUG
								printf("block1中有效指令未找到, 0x20有标记但没找到block1中有效指令\n");
								
#endif
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
									goto research_hook1;
								}
								else
								{
									printf("所有均已搜完,非virut,退出\n");
									goto end4;
								}
							}
						}

						if (jmptimes == 3)
						{
							if (block2_confirmed == 0)
							{
#if DEBUG
								printf("block2中有效指令未找到, 0x20有标记但没找到block2中有效指令\n");
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
									goto research_hook1;
								}
								else
								{
									printf("所有均已搜完,非virut,退出\n");
									goto end4;
								}
								
							}
						}

						if (jmptimes == 4)
						{
							if (block3_confirmed == 0)
							{
#if DEBUG
								printf("block3中有效指令未找到, 0x20有标记但没找到block3中有效指令\n");
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
									goto research_hook1;
								}
								else
								{
									printf("所有均已搜完,非virut,退出\n");
									goto end4;
								}
								
							}
						}
						

						nextRVA = prevRVA + i + 5 + *(int*)(pcode + i + 1);
						if ((nextRVA > pLastSec->VirtualAddress) && (nextRVA < pLastSec->VirtualAddress + pLastSec->SizeOfRawData))  //这是跳转到尾节病毒代码的最终之跳..
						{
							if (block1_confirmed&&block2_confirmed&&block3_confirmed&&block4_confirmed)
							{
								if (jmptimes == 3 || jmptimes == 4) //现在看的, 就只有4块和5块这两种情况..
								{
									CodeEntry2_RVA = nextRVA;
#if DEBUG
									printf("尾节病毒代码入口点为%x\n", CodeEntry2_RVA);
#endif // DEBUG
									goto oepvir_decode;
								}
								else
								{
#if DEBUG
									printf("oep节节尾病毒代码解析错误\n");
#endif
									goto end4;
								}
							}
							else
							{
#if DEBUG
								printf("部分oep节尾病毒代码有效指令未找到\n");
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
									goto research_hook1;
								}
								else
								{
									printf("所有均已搜完,非virut,退出\n");
									goto end4;
								}
								goto end4;
							}
							
						}
						break;
					}
					if (*(pcode + i) == 0xeb)
					{
						if (jmptimes == 2)  //这里用==没问题, 因为都是一次一次往上加的..后面尾部解析的nume8call就不行.. 得用>=
						{
							if (block1_confirmed == 0)
							{
#if DEBUG
								printf("block1中有效指令未找到, 0x20有标记但没找到block1中有效指令\n");
#endif
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
									goto research_hook1;
								}
								else
								{
									printf("所有均已搜完,非virut,退出\n");
									goto end4;
								}
								
							}
						}

						if (jmptimes == 3)
						{
							if (block2_confirmed == 0)
							{
#if DEBUG
								printf("block2中有效指令未找到, 0x20有标记但没找到block2中有效指令\n");
								
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
									goto research_hook1;
								}
								else
								{
									printf("所有均已搜完,非virut,退出\n");
									goto end4;
								}
								
							}
						}

						if (jmptimes == 4)         //这个其实不可能会在这儿了.. 因为最后一条必定是E9跳的.
						{
							if (block3_confirmed == 0)
							{
#if DEBUG
								printf("block3中有效指令未找到, 0x20有标记但没找到block3中有效指令\n");
								
#endif // DEBUG
								if (oepsearchpos < oepremainbytes - 0x10)
								{
									printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
									goto research_hook1;
								}
								else
								{
									printf("所有均已搜完,非virut,退出\n");
									goto end4;
								}
								
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
							printf("解析oep节节尾跳转出错\n");
#endif // DEBUG
							if (oepsearchpos < oepremainbytes - 0x10)
							{
								printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
								goto research_hook1;
							}
							else
							{
								printf("所有均已搜完,非virut,退出\n");
								goto end4;
							}
						}
					}
					else
					{
#if DEBUG
						printf("解析oep节节尾跳转出错\n");
#endif // DEBUG

						if (oepsearchpos < oepremainbytes - 0x10)
						{
							printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
							goto research_hook1;
						}
						else
						{
							printf("所有均已搜完,非virut,退出\n");
							goto end4;
						}
					}
				}
				pcode = data + RVA2FO(pish, numOfSections, nextRVA);
				prevRVA = nextRVA;
				++jmptimes;

				if (jmptimes >= 5)   //最多只可能跳4次, 然后不会经过这儿
				{
#if DEBUG
					printf("oep节尾病毒代码跳转死循环, 退出\n");
#endif

					if (oepsearchpos < oepremainbytes - 0x10)
					{
						printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
						goto research_hook1;
					}
					else
					{
						printf("所有均已搜完,非virut,退出\n");
						goto end4;
					}
				}

			}

			
oepvir_decode:

			CodeEntry1_Base_RVA = block_RVA[0];
			for (int j = 0; j < jmptimes; ++j)
			{
				CodeEntry1_Base_RVA = min(CodeEntry1_Base_RVA, block_RVA[j]);     //获取最小地址
			}

			//对尾节数据进行恢复操作:
			//首先先确定正确的数据:
			//我以block2中的数据为基准, 因为解密的指令比较准确.. 而且我估计这个大部分情况下也应该只有一个..

			if (numofblock2_trueins != 1)
			{
#if DEBUG
				printf("有多条有效加减解密指令,退出\n");
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

					if (indexAll[m] == index)  //再和block3中的确认一遍
					{
#if DEBUG
						printf("再次确认block3 index成功\n");
#endif
					}
				}
			}

			

			if (virutkind == 1)
			{
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
			else if (virutkind == 2)
			{
				WORD *pTemp = (WORD*)(data + RVA2FO(pish, numOfSections, CodeEntry2_base_RVA));
				for (int i = 0; i <= CodeEntry2_base_size / 2; ++i)
				{
					if (method == 1)
					{
						*(pTemp + i) += LOWORD(key1);
					}
					if (method == 0)
					{
						*(pTemp + i) -= LOWORD(key1);
					}
				}
			}
			else
			{
				printf("未知尾节加密方式, 退出\n");
				goto end4;
			}


			

		}

	FuckCode2:

		if (CodeEntry2_RVA)  //开始解析尾节的跳转, 找到最后那一跳      //有些样本是直接入口在尾部, 所以尾部跳转时也得确认有效代码.
		{
			virutkind = virutkind == -1 ? 1 : virutkind; //如果是直接跳到codeentry2解析的, 那么默认先virutkind为1, 如果失败, 再进行virutkind为2的处理
			BYTE *pLastCode = data + RVA2FO(pish, numOfSections, CodeEntry2_RVA);
			DWORD prevRVA = CodeEntry2_RVA;
			DWORD nextRVA = 0;
			int num_e8call = 0;
			int times = 0;
			BOOL findlast = FALSE;
			int backvalue1 = 0, backvalue2 = 0;
			int sig_confirmed1 = 0, sig_confirmed2 = 0;   //4个检查差不多够了.
			int sig_confirmed3 = 0, sig_confirmed4 = 0;
			int jmptimes = 0;

refuck:
			pLastCode = data + RVA2FO(pish, numOfSections, CodeEntry2_RVA);
			prevRVA = CodeEntry2_RVA;
			nextRVA = 0;
			num_e8call = 0;
			times = 0;
			findlast = FALSE;
			backvalue1 = 0, backvalue2 = 0;
			sig_confirmed1 = 0, sig_confirmed2 = 0;  
			sig_confirmed3 = 0, sig_confirmed4 = 0;
			jmptimes = 0;

			while (1)
			{   
				if (virutkind == 1)  
				{
					for (int i = 0; i < 0x100; )    //每一块一般就3~5条指令, 加上一些垃圾代码, 根据概率, 基本会<0x100   //在新一代中, 每一块的指令数是0x21, 所以这个0x100的判断貌似有点不够 
					{
						if (*(pLastCode + i) == 0xE8)   //根据已经经过的e8 call数量, 来定位自身代码的相应位置,     需要注意call esi是ff d6.. 差点因为这个数错了..
						{                               //经过1次e8后, 遇到的jz, 0f 84 xx xx xx xx就直接跳到目的位置
														//经过4次e8后, 遇到的第一个jz不管, 第二个jz, 0f 84 xx xx xx xx也直接跳到目的地
														//经过8次e8后, 遇到的第一个c3后直接跳过5个字节, 继续反汇编, 此时找到lea ecx,[ecx+0] 8d 49 00 + e9/eb xx序列, 后面的jmp目的地址就是body的基地址了!!
							++num_e8call;
							if (num_e8call == 1)  //这里不一定是E8 00 00 00 00, 不过没什么影响.
							{
								backvalue1 = i + 5 + prevRVA + pinh->OptionalHeader.ImageBase;
#if DEBUG
								printf("用于计算回跳点的值1:%x\n", backvalue1);
#endif
								//第一个call也要跳, 以后的call全部无视
								nextRVA = prevRVA + i + 5 + *(int*)(pLastCode + i + 1);
								if ((nextRVA > pLastSec->VirtualAddress) && (nextRVA < pLastSec->VirtualAddress + pLastSec->SizeOfRawData))
								{
									break;  //符合条件的时候才break; 不符合条件的就当没发生继续
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
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
							}

							if (*(pLastCode + i) == 0x81 && *(pLastCode + i + 1) == 0x74
								&& *(pLastCode + i + 2) == 0x24 && *(pLastCode + i + 3) == 0x20)
							{
								sig_confirmed2 = 1;
								backvalue2 = *(int*)(pLastCode + i + 4);
								calc_backupvaluemethod = 2;
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
							}

							if (*(pLastCode + i) == 0x81 && *(pLastCode + i + 1) == 0x6c
								&& *(pLastCode + i + 2) == 0x24 && *(pLastCode + i + 3) == 0x20)
							{
								sig_confirmed2 = 1;
								backvalue2 = *(int*)(pLastCode + i + 4);
								calc_backupvaluemethod = 3;
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
							}

							if (*(pLastCode + i) == 0x0f && *(pLastCode + i + 1) == 0x84)  //jz pe_find 直接跳
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
								if (times == 2)  //第二个jz
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
							//此时eb或e9肯定就跟着的.
							if (*(pLastCode + i + 3) == 0xeb)
							{
								bodybase_RVA = prevRVA + i + 3 + 2 + *(int8_t*)(pLastCode + i + 3 + 1);  //算出跳转的目的地址
#if DEBUG
								printf("尾节最终block块RVA为%x\n", bodybase_RVA);
#endif // DEBUG
								goto outofwhile;
							}

							if (*(pLastCode + i + 3) == 0xe9)
							{
								bodybase_RVA = prevRVA + i + 3 + 5 + *(int*)(pLastCode + i + 3 + 1);
#if DEBUG
								printf("尾节最终block块RVA为%x\n", bodybase_RVA);
#endif // DEBUG
								goto outofwhile;
							}

						}

						//把E9放EB前面,这样更好一些.
						if (*(pLastCode + i) == 0xE9)
						{
							if (num_e8call >= 2)
							{
								if (sig_confirmed1 == 1 && sig_confirmed2 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n",virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}

							if (num_e8call >= 5)
							{
								if (sig_confirmed3 == 1 && sig_confirmed4 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}

							nextRVA = prevRVA + i + 5 + *(int*)(pLastCode + i + 1);
							if ((nextRVA > pLastSec->VirtualAddress) && (nextRVA < pLastSec->VirtualAddress + pLastSec->SizeOfRawData))
							{

								break;  //符合条件的时候才break; 不符合条件的就当没发生继续
							}
						}
						if (*(pLastCode + i) == 0xeb)
						{
							if (num_e8call >= 2)
							{
								if (sig_confirmed1 == 1 && sig_confirmed2 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}

							if (num_e8call >= 5)
							{
								if (sig_confirmed3 == 1 && sig_confirmed4 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
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
								if (virutkind < 2)
								{
#if DEBUG
									printf("非变种%d,换种方式\n", virutkind);
#endif
									++virutkind;
									goto refuck;
								}
								else
								{
#if DEBUG
									printf("可能不是virut样本,退出\n");
#endif
									goto end4;
								}
							}
						}
						else
						{
							if (virutkind < 2)
							{
#if DEBUG
								printf("非变种%d,换种方式\n", virutkind);
#endif
								++virutkind;
								goto refuck;
							}
							else
							{
#if DEBUG
								printf("可能不是virut样本,退出\n");
#endif
								goto end4;
							}
						}
					}
				}

				if (virutkind == 2)  //想了想, 为了干净一些还是另起炉灶吧, 不然全部混在一起, 以后看的时候会有点恶心.
				{
					for (int i = 0; i < 0x30 * 0xf; )  //根据概率, 绝对够用了.
					{
						
						if (num_e8call == 0)       //? 为什么这块代码在调试的时候被跳过了??   这块代码居然消失了???
						{
							if (*(DWORD*)(pLastCode + i) == 0xfe243c83)  // cmp dword ptr[esp], -2
							{
								sig_confirmed1 = 1;            //我靠, 我居然把=写成了==, 然后编译器看我什么都没做,直接给我全优化了..
							}
						}

						if (num_e8call == 1)
						{
							if (*(pLastCode + i) == 0xff && *(pLastCode + i + 1) == 0x73 && *(pLastCode + i + 2) == 0x3C)  //push dword ptr [ebx+0x3c]
							{
								sig_confirmed2 = 1;
							}
						}

						if (num_e8call == 2)
						{
							if (*(DWORD*)(pLastCode + i) == 0x44247489)  // mov [esp+44h],esi
							{
								sig_confirmed3 = 1;
							}
						}

						if (num_e8call == 5)
						{
							if (*(pLastCode + i) == 0x64 && *(WORD*)(pLastCode + i + 1) == 0x158b && *(DWORD*)(pLastCode + i + 3) == 0x30)  // mov edx, large fs:30h
							{
								sig_confirmed4 = 1;
							}
						}

						if (num_e8call == 8 && *(pLastCode + i) == 0xc3)
						{
							findlast = TRUE;
							i += 5;
							continue;
						}

						if (findlast && *(WORD*)(pLastCode + i) == 0xff8b)  //mov edi, edi
						{
							//此时eb或e9肯定就跟着的.
							if (*(pLastCode + i + 2) == 0xeb)
							{
								bodybase_RVA = prevRVA + i + 2 + 2 + *(int8_t*)(pLastCode + i + 2 + 1);  //算出跳转的目的地址
#if DEBUG
								printf("尾节最终block块RVA为%x\n", bodybase_RVA);
#endif // DEBUG
								goto outofwhile;
							}

							if (*(pLastCode + i + 2) == 0xe9)
							{
								bodybase_RVA = prevRVA + i + 2 + 5 + *(int*)(pLastCode + i + 2 + 1);
#if DEBUG
								printf("尾节最终block块RVA为%x\n", bodybase_RVA);
#endif // DEBUG
								goto outofwhile;
							}
						}

						if (*(pLastCode + i) == 0xe8)
						{
							++num_e8call;
							if (num_e8call == 1)  //这里不一定是E8 00 00 00 00, 不过没什么影响.
							{
								backvalue1 = i + 5 + prevRVA + pinh->OptionalHeader.ImageBase;
#if DEBUG
								printf("用于计算回跳点的值1:%x\n", backvalue1);
#endif
							}
							if (num_e8call == 4) //这个call要进去
							{
								nextRVA = prevRVA + i + 5 + *(int*)(pLastCode + i + 1);
								break;
							}

						}
						if (*(pLastCode + i) == 0xe9)
						{
							if (num_e8call >= 1)
							{
								if (sig_confirmed1 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}

							if (num_e8call >= 2)
							{
								if (sig_confirmed2 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}
							
							if (num_e8call >= 3)
							{
								if (sig_confirmed3 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}

							if (num_e8call >= 6)
							{
								if (sig_confirmed4== 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}

							nextRVA = prevRVA + i + 5 + *(int*)(pLastCode + i + 1);
							if ((nextRVA > pLastSec->VirtualAddress) && (nextRVA < pLastSec->VirtualAddress + pLastSec->SizeOfRawData))
							{
								break;  //符合条件的时候才break; 不符合条件的就当没发生继续
							}
						}
						if (*(pLastCode + i) == 0xeb)
						{
							if (num_e8call >= 1)
							{
								if (sig_confirmed1 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}

							if (num_e8call >= 2)
							{
								if (sig_confirmed2 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}

							if (num_e8call >= 3)
							{
								if (sig_confirmed3 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
								}
							}

							if (num_e8call >= 6)
							{
								if (sig_confirmed4 == 1)
								{
#if DEBUG
									;   //是的话什么都不做, 不是的话就得退出了.
#endif
								}
								else
								{
									if (virutkind < 2)
									{
#if DEBUG
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
									else
									{
#if DEBUG
										printf("可能不是virut样本,退出\n");
#endif
										goto end4;
									}
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
								if (virutkind < 2)
								{
#if DEBUG
									printf("非变种%d,换种方式\n", virutkind);
#endif
									++virutkind;
									goto refuck;
								}
								else
								{
#if DEBUG
									printf("可能不是virut样本,退出\n");
#endif
									goto end4;
								}
							}
						}
						else
						{
							if (virutkind < 2)
							{
#if DEBUG
								printf("非变种%d,换种方式\n", virutkind);
#endif
								++virutkind;
								goto refuck;
							}
							else
							{
#if DEBUG
								printf("可能不是virut样本,退出\n");
#endif
								goto end4;
							}
						}
					}

				} //改完了, 出乎意料的简单啊, 可能是我这种跳转解析模式的优越性吧
				

				pLastCode = data + RVA2FO(pish, numOfSections, nextRVA);
				prevRVA = nextRVA;
				++jmptimes;
				if (jmptimes >= 0x100)        //块数方面, 旧一代的块数大概在0x64, 新一代的块数在0x79, 所以这个判断应该还可以兼容.
				{
#if DEBUG
					printf("跳转次数过多,可能出现死循环,该样本非virut\n");
#endif 
					goto end4;
				}
			}//end of while(1)

		outofwhile:



			// 现在bodybase_RVA有了, 准备去解密bodybase_RVA+0x53c处的数据
			//+539 00 c3  利用这两个数据, 利用加密算法的漏洞算出key, 
			WORD keyfull;
			BYTE* pBlock = data + RVA2FO(pish, numOfSections, bodybase_RVA) + 0;  

			if (virutkind == 1)
			{
				pBlock = pBlock + 0x53c - 1;
				BYTE db_base_minus3_before = 0x00, db_base_minus3_after;
				BYTE db_base_minus2_before = 0xc3, db_base_minus2_after;
				BYTE key1, key2;


				db_base_minus3_after = *(data + RVA2FO(pish, numOfSections, bodybase_RVA) + 0x53c - 3);
				db_base_minus2_after = *(data + RVA2FO(pish, numOfSections, bodybase_RVA) + 0x53c - 2);

				key1 = db_base_minus3_after ^ db_base_minus3_before;
				key2 = db_base_minus2_after ^ db_base_minus2_before;


				key1 *= 0xd;
				keyfull = ((WORD)key1 << 8) | key2;

				//然后解密个0x70 * 8字节数 , 因为块最多0x64个左右..
				for (int i = 0; i < 0x70 * 8; ++i)
				{
					keyfull *= 0xd;
					keyfull = HIBYTE(keyfull) | ((WORD)(LOBYTE(keyfull)) << 8); //xchg dh,dl
					*(pBlock + i) ^= LOBYTE(keyfull);         //注意,调试的时候,每次都会改变文件的内容,所以要每次备份原版文件, 或者再改变一次, 就变成了原样了.
				}
			}

			if (virutkind == 2)
			{
				// 这回不麻烦了, 就取body开始的5个字节 e9 10 01 00 00 暴力算
				BYTE* db_base_0_after = data + RVA2FO(pish, numOfSections, bodybase_RVA) + 0;
				pBlock = pBlock + 0x59e - 1;
				
				for (DWORD i = 1; i <= 0xffff; ++i)   //这里用DWORD而不是word是为了防止0ffff执行后++i,又变成0, 成了死循环.
				{
					BYTE db_before[5] = { 0xe9,0x10,0x01,0x00,0x00 };
					int temp = i;
					for (int j = 0; j < 5; ++j)
					{
						db_before[j] += HIBYTE(temp);
						temp *= 0xefb5;
						db_before[j] ^= LOBYTE(temp);
						
						temp = HIBYTE(temp) | ((WORD)(LOBYTE(temp)) << 8);
					}
					if (!memcmp(db_base_0_after, db_before, 5))
					{
						//说明找到了
						keyfull = i;
						break;
					}
				}

				//然后算出body+ 0x59e - 1时的keyfull

				for (int i = 0; i < 0x59e - 1 ; ++i)
				{
					keyfull *= 0xefb5;
					keyfull = HIBYTE(keyfull) | ((WORD)(LOBYTE(keyfull)) << 8);
				}

				//开始解密

				for (int i = 0; i < 0xa0 * 8; ++i) // 后面的数据破坏就破坏了, 无所谓
				{
					WORD temp = keyfull * 0xefb5;
					*(pBlock + i) = (*(pBlock + i) ^ LOBYTE(temp)) - HIBYTE(keyfull);
					keyfull = HIBYTE(temp) | ((WORD)(LOBYTE(temp)) << 8);
				}

				printf("fuckdamnit");
			}

			

			

			//解密完毕, 找到CodeEntry2_Base_RVA


			//WORD* pBodyBlock = (WORD*)(pBlock + 1 + (*pBlock - 1) * 0x8); //找到body的block  //发现解密后的这个blocknum有问题, 还是手动去找算了..

			WORD *pBodyBlock = NULL;
			for (int i = 0; i < 0x100; ++i)         //扩大了, 因为新一代的块数上限较多
			{
				if (*(WORD*)(pBlock + 1 + i * 8) >= 0x3000 && *(WORD*)(pBlock + 1 + i * 8) <= 0x9000                    //为了通用性
					&& *(WORD*)(pBlock + 1 + i * 8) == (*(WORD*)(pBlock + 1 + 6 + i * 8)&0x7fff))                       //稍微检查一下
				{
					pBodyBlock = (WORD*)(pBlock + 1 + i * 8);    
					break;
				}
			}
			if (pBodyBlock == NULL || *(pBodyBlock + 1) < 0x100)   //body的beforeoffset, 目前看到两个: 0x1e8, 和 0x300
			{
#if DEBUG
				printf("body的beforeoffset有问题\n");
#endif // DEBUG

				goto end4;
			}

			CodeEntry2_base_RVA = bodybase_RVA - *(pBodyBlock + 2);

			//我发现, 如果是通过设置入口点方式的话, 那么就不会有那两条指令... c6 05和c7 05, 所以只有当有HOOK时才去搜这两条指令
			if (hasHook1 == TRUE)
			{
				DWORD CodeToSearch_RVA = 0;
				//接下来寻找包含before_offset 173的block
				//新一代中是包含before_offset b4的block 
				for (int i = 0; i < 0x100; ++i)
				{
					PWORD pTemp = (PWORD)(pBlock + 1 + i * 8);

					if (virutkind == 1)
					{
						if ((0x173 >= *(pTemp + 1)) && (0x173 < (*(pTemp + 1) + *pTemp)))
						{
							CodeToSearch_RVA = CodeEntry2_base_RVA + *(pTemp + 2);

#if DEBUG
							printf("包含那两条恢复指令的病毒代码块RVA为%x\n", CodeToSearch_RVA);
#endif // DEBUG
							break;
						}
					}
					if (virutkind == 2)
					{
						if ((0xb4 >= *(pTemp + 1)) && (0xb4 < (*(pTemp + 1) + *pTemp)))
						{
							CodeToSearch_RVA = CodeEntry2_base_RVA + *(pTemp + 2);

#if DEBUG
							printf("包含那两条恢复指令的病毒代码块RVA为%x\n", CodeToSearch_RVA);
#endif // DEBUG
							break;
						}
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
						printf("在%x处恢复一个字节值为%x\n", Recover1_VA, Recover1_Value);
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
						printf("在%x处恢复四个字节值为%x\n", Recover2_VA, Recover2_Value);
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
							printf("找那两条mov指令位置出错\n");
#endif // DEBUG

							goto end4;
						}
					}
					else
					{
#if DEBUG
						printf("找那两条mov指令位置出错\n");
#endif // DEBUG

						goto end4;
					}
				}

				//找到这两条之后就把对应位置的数据给他恢复了

				*(data + RVA2FO(pish, numOfSections, Recover1_VA - pinh->OptionalHeader.ImageBase)) = Recover1_Value;
				*(DWORD*)(data + RVA2FO(pish, numOfSections, Recover2_VA - pinh->OptionalHeader.ImageBase)) = Recover2_Value;
			}


			//这时候得考虑恢复原OEP,因为他有可能是把OEP直接设置到尾节或入口节尾部垃圾代码.
			//所以当没有hook1点时, 就把OEP设置为Recover1_VA-Imagebase和Recover2_VA-ImageBase中较小的那一个

			if (hasHook1 == FALSE)
			{
				if (virutkind == 2)  //这时候就得找到backupvalue2
				{
					DWORD CodeToSearch_RVA = 0;
					
					//接下来寻找包含before_offset 0xfa的block //这里有个81 44 24 24 dd_backvalue2
					for (int i = 0; i < 0x100; ++i)
					{
						PWORD pTemp = (PWORD)(pBlock + 1 + i * 8);

						if ((0xfa >= *(pTemp + 1)) && (0xfa < (*(pTemp + 1) + *pTemp)))
						{
							CodeToSearch_RVA = CodeEntry2_base_RVA + *(pTemp + 2);

#if DEBUG
							printf("包含backvalue2指令的病毒代码块RVA为%x\n", CodeToSearch_RVA);
#endif // DEBUG
							break;
						}
					}

					BYTE *pSearch = data + RVA2FO(pish, numOfSections, CodeToSearch_RVA);
					for (int i = 0; i < 0x100; )
					{
						if (*(DWORD*)(pSearch + i) == 0x24244481)   //add dword ptr [esp+0x24], dd_backvalue2  目前我就看到第一种的, 顺便把后两种给补了..
						{
							calc_backupvaluemethod = 1;
							backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
							printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
							break;
						}

						if (*(DWORD*)(pSearch + i) == 0x24247481)   //xor dword ptr [esp+0x24], dd_backvalue2
						{
							calc_backupvaluemethod = 2;
							backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
							printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
							break;
						}

						if (*(DWORD*)(pSearch + i) == 0x24246c81)   //sub dword ptr [esp+0x24], dd_backvalue2
						{
							calc_backupvaluemethod = 3;
							backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
							printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
							break;
						}

						int count = cs_disasm(handle, pSearch + i, 0xf, 0, 1, &insn);
						if (count == 1)
						{
							i += insn[0].size;
							cs_free(insn, count);
							if (i >= 0x100)
							{
#if DEBUG
								printf("找backvalue2指令位置出错\n");
#endif // DEBUG

								goto end4;
							}
						}
						else
						{
#if DEBUG
							printf("找backvalue2指令位置出错\n");
#endif // DEBUG

							goto end4;
						}
					}

				}

				//这时候通过两个块来计算出原oep值
				//尾节开始代码的的e9 xx 00 00 00 00			

				const char *fuck = "god knows";
				if (calc_backupvaluemethod == 1)
				{
					pinh->OptionalHeader.AddressOfEntryPoint = backvalue1 + backvalue2 - pinh->OptionalHeader.ImageBase;
					fuck = "加法";
				}
				if (calc_backupvaluemethod == 2)
				{
					pinh->OptionalHeader.AddressOfEntryPoint = (backvalue1 ^ backvalue2) - pinh->OptionalHeader.ImageBase;
					fuck = "异或";
				}
				if (calc_backupvaluemethod == 3)
				{
					pinh->OptionalHeader.AddressOfEntryPoint = (backvalue1 - backvalue2) - pinh->OptionalHeader.ImageBase;
					fuck = "减法";
				}
				

#if DEBUG
				printf("backvalue计算方法为:%s\n重新设置PE头中的OEP为%x\n", fuck, pinh->OptionalHeader.AddressOfEntryPoint);
#endif // DEBUG

			}

			//开始恢复节表,sizeofimage,并设置文件末尾
			//先恢复尾节表
			DWORD LastSectionReduce_VSize = pLastSec->Misc.VirtualSize - (CodeEntry2_base_RVA - pLastSec->VirtualAddress);
			DWORD LastSectionReduce_RSize = pLastSec->SizeOfRawData - (RVA2FO(pish, numOfSections, CodeEntry2_base_RVA) - pLastSec->PointerToRawData);
			
#if DEBUG
			printf("将尾区段的VSize减小%x RSize减小%x\n", LastSectionReduce_VSize, LastSectionReduce_RSize);
			printf("将PE头的SizeOfImage减小%x 将文件大小减小%x\n", LastSectionReduce_VSize, LastSectionReduce_RSize);
#endif // DEBUG

			pLastSec->Misc.VirtualSize -= LastSectionReduce_VSize;
			pLastSec->SizeOfRawData -= LastSectionReduce_RSize;
			pinh->OptionalHeader.SizeOfImage -= LastSectionReduce_VSize;

			AdjustSize = TRUE;
			dwFileSize -= LastSectionReduce_RSize;

			//如果这个样本有入口节病毒代码
			if (CodeEntry1_RVA)
			{
				DWORD OEPSectionReduce_VSize = pOepSec->Misc.VirtualSize - (CodeEntry1_Base_RVA - pOepSec->VirtualAddress);
				DWORD OEPSectionReduce_RSize = pOepSec->SizeOfRawData - (RVA2FO(pish, numOfSections, CodeEntry1_Base_RVA) - pOepSec->PointerToRawData);


				//据我所知, oep这个节表就是简单地进行了: 病毒代码生成指针指向vsize+vaddress, 然后vsize = rsize. 一般vsize向上对filealign取天花板就是rsize.
				//所以, 我就把数据清空, 再把vsize剪一下就行了..
				pOepSec->Misc.VirtualSize -= OEPSectionReduce_VSize;

				if (pOepSec->VirtualAddress + pOepSec->Misc.VirtualSize >= (pOepSec + 1)->VirtualAddress)  //意味着会清到下一个区段的数据
				{
#if DEBUG
					printf("入口节节尾病毒数据覆盖至下一区段, 本文件已经永久损坏\n");
					goto end4;
#endif
				}
				memset((BYTE*)(data + pOepSec->PointerToRawData + pOepSec->Misc.VirtualSize), 0, OEPSectionReduce_VSize);

#if DEBUG
				printf("将OEP区段表的VSize减小%x\n", OEPSectionReduce_VSize);
				printf("将OEP区段的raddr: %x处的%x字节清0\n", pOepSec->PointerToRawData + pOepSec->Misc.VirtualSize, OEPSectionReduce_VSize);
#endif // DEBUG


			}

			//清除感染标记
			*(DWORD*)(data + 0x20) = 0;

		} // end of if codeentry2

	}

#if DEBUG
	if (virutkind == 0)
	{
		printf("确认非virut变种,不处理\n");
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
	char szFile[260] = { "C:\\Users\\bj2017\\OneDrive\\source\\VirutInfectedFileRecovery\\VirutInfectedFileRecovery\\test" };
	ScanFile(szFile, FALSE);


	//char szFilePath[260] = { "C:\\Users\\bj2017\\OneDrive\\source\\VirutInfectedFileRecovery\\VirutInfectedFileRecovery\\fuckittest" };
	//WIN32_FIND_DATA data;
	//HANDLE hFind;
	//char cFullPath[260];
	//char cNewPath[260];
	//sprintf_s(cFullPath, "%s\\*.*", szFilePath);
	//hFind = FindFirstFile(cFullPath, &data);
	//do
	//{
	//  if ((!strcmp(".", data.cFileName)) || (!strcmp("..", data.cFileName)))
	//  {
	//		continue;
 //     }
	//  // MessageBox(NULL,data.cFileName,"Look",0);
	//  sprintf_s(cFullPath, "%s\\%s", szFilePath, data.cFileName);
	//  printf("修复文件%s\n", data.cFileName);
	//  ScanFile(cFullPath,FALSE);
	//  printf("\n\n");
	//} while (FindNextFile(hFind, &data));


	return 0;
}