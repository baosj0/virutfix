//fucked by baoshijin
//last modified date: 2019.1.12



#include "virut_sig.h"
#include "include/capstone.h"

#pragma comment(lib,"capstone_dll.lib")

#define DEBUG 1      //输出调试信息
#define MYTEST 1     //试验中碰到多层加密的, 那就把这个设为0, 一层一层去剥开, 看有没有没见过的变种



//比较tocmp处的字节, whatwewant写特征码字符串 
//仅限十六进制, 大小写无所谓, 空格无所谓, 半字节匹配, 问号匹配任意.
//例如arg2: "68 ?? ?? ?? ??"
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
		BYTE temp = tocmp[i / 2];  //当前要比较的字节
		if (whatwewant[j] >= 0x30 && whatwewant[j] <= 0x39)
		{
			if (i % 2 == 0)  //说明是比较高位
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
			BYTE fuck = whatwewant[j] >= 0x61 ? whatwewant[j] - 0x20 : whatwewant[j]; // 转换成大写统一处理

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

		++i, ++j; //下一个

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





//这个函数用处不大, 暂时放着. 别用.
//我直接用代码里的标志判断是哪一代. 一代有多个变种标志值, 但仍然是一代.
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
	int calc_backupvaluemethod = 0;       //1 代表加法  2代表xor 3代表减法
	int oepsearchpos = 0, oepremainbytes = 0;
	BYTE *pcode = NULL;
    DWORD dwTemp = 0;
    BOOL success = FALSE;
    DWORD reCrackOff = 0;

	//参数检查
	if (szFileName == NULL || !strcmp(szFileName, ""))
	{
		result = -1;
		goto end1;
	}

	
    hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

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
 
    data = (BYTE*)VirtualAlloc(NULL, dwFileSize, 0x3000, PAGE_READWRITE);
    ReadFile(hFile, data, dwFileSize, &dwTemp, NULL);
    bFreeFlag = TRUE;
    if (dwTemp != dwFileSize)
    {
        result = -1;
        goto end3;
    }

	if (data == 0)
	{
		result = -1;
		goto end3;
	}


	pidh = (PIMAGE_DOS_HEADER)data;

	if (pidh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		result = -1;
		goto end4;
	}

	if ((DWORD)pidh->e_lfanew >= 0x10000) 
	{
		result = -1;
		goto end4;
	}

	pinh = (PIMAGE_NT_HEADERS)(data + pidh->e_lfanew);

	pish = (PIMAGE_SECTION_HEADER)(pinh + 1);

	if (pinh->Signature != IMAGE_NT_SIGNATURE)
	{
		result = -1;
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

	

	//virutkind = MatchVirutCE1(data);
	
	if (1 == 1)
	{
#if DEBUG
        /*if (virutkind == 1)
        {
            printf("确认为已知变种1, 开始进行处理\n");
        }*/
		if (1 == 1)
		{
#if MYTEST
			PIMAGE_SECTION_HEADER pjunk = &pish[pinh->FileHeader.NumberOfSections - 1];
			char tempname[8] = { 0 };
			memcpy(tempname, pjunk->Name, 8);
			
			if (checksecname(tempname))
			{
				if (pjunk->Misc.VirtualSize == 0x1000 && pjunk->Characteristics == 0xc000'0000 && pjunk->SizeOfRawData == 0)
				{
					//先修复PE头的问题. 
					// | xx | 00000   ==>  |xx | yy
					// | xx | kkkk    ==>  |xx|yy|kkkk
					//这个貌似不大好判断, 还是不搬了..
					pinh->OptionalHeader.SizeOfImage -= pinh->OptionalHeader.SectionAlignment;
					memset(pjunk, 0, 0x28);
					pinh->FileHeader.NumberOfSections -= 1;

#if DEBUG
					printf("清除垃圾区段数据成功,SizeOfImage减小%x\n", pinh->OptionalHeader.SectionAlignment);
#endif
					
					//因为rawsize是0, 所以貌似不会计算到文件大小中去, 所以也不用添加相关逻辑..
				}
				else
				{
					printf("多次感染样本, 无法修复, 退出\n");
					goto end4;
				}
			}
			else
#endif
			{
				printf("未知样本, 尝试处理\n");
			}


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
			bNoOEPSecCode = 1;
			CodeEntry2_RVA = oep;
			goto FuckCode2;
		}

		pOepSec = FindRVASection(pish, numOfSections, oep);

		if (pOepSec == NULL)
		{
#if DEBUG
			printf("找不到入口点所属于的节,退出\n");
			goto end4;
#endif
		}

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
                hasHook1 = FALSE;
#if DEBUG
				printf("入口点在入口节节尾\n");
#endif // DEBUG
				CodeEntry1_RVA = oep;
				goto FuckCode1;
			}
		}
		

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

					//说明跳到了oep节尾
					if (pOepSec->VirtualAddress + pOepSec->SizeOfRawData - pinh->OptionalHeader.FileAlignment <= dest &&
						dest <= pOepSec->VirtualAddress + pOepSec->SizeOfRawData)
					{
						bNoOEPSecCode = 0;
						hook1pos_RVA = oep + i;
						CodeEntry1_RVA = dest;
						oepsearchpos = i + 5; //如果后面解析oepblock失败, 那么就会跳回来继续搜索
#if DEBUG
						printf("HOOK点1跳到了OEP节尾: hook点1 %x 入口点节尾%x\n", hook1pos_RVA, dest);
#endif // DEBUG
						break;
					}
						
					
					//说明跳到了尾节
					if (dest >= pLastSec->VirtualAddress && dest < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)
					{
						bNoOEPSecCode = 1;
						hook1pos_RVA = oep + i;
						CodeEntry2_RVA = dest;
#if DEBUG
						printf("HOOK点1跳到了尾节: hook点1 %x 节尾%x\n", hook1pos_RVA, dest);
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
					//printf("反汇编指令失败,跳过当前字节\n");   //有点多, 去了..
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
			DWORD block_RVA[5+1] = { 0 };  //尾部的0作为一个标记
			int block1_confirmed = 0, block2_confirmed, block3_confirmed, block4_confirmed;
			int index = -1;
			int indexAll[10] = { 0 };
			DWORD key1 = 0;
			DWORD key1All[10] = { 0 };
			int method = -1; //1表示add, 0表示sub 2表示rol 3表示ror 4表示adc 5表示sbb 初始为-1,这样出现意外情况时,使其出错
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
							CodeEntry2_base_size = *(DWORD*)(pcode + i + 1);            //在1de86992_58c的样本中, 发现有mov ecx,xxx 和mov edx,yyy两个同时出现.. 
							if (CodeEntry2_base_size <= 0x8000 && CodeEntry2_base_size >= 0x200)
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
								printf("block1中有效指令找到\n");
								printf("尾节块大小为%x\n 入口节尾病毒使用的寄存器为%s\n", CodeEntry2_base_sizeAll[numofblock1_trueins - 1], regname[numofblock1_trueins - 1]);
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
								printf("block1中有效指令找到\n");
								printf("尾节块大小为%x\n 入口节尾病毒使用的寄存器为%s\n", CodeEntry2_base_sizeAll[numofblock1_trueins - 1], regname[numofblock1_trueins - 1]);
#endif // DEBUG

							}
						}
					}

					if (jmptimes == 1 || jmptimes == 2)
					{
                        //add dword; sub dword
						if (*(pcode + i) == 0x81 && (*(pcode + i + 1) == 0x80 || *(pcode + i + 1) == 0x81 ||
							*(pcode + i + 1) == 0x82 || *(pcode + i + 1) == 0xa8 || *(pcode + i + 1) == 0xa9 || *(pcode + i + 1) == 0xaa))
						{

							if (*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
								*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //判断一下解密的地址肯定是在尾节.
							{
								decryptsize = 4;
								block2_confirmed = 1;
								           
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

                        //add byte;sub byte
						if (*(pcode + i) == 0x80 && (*(pcode + i + 1) == 0x80 || *(pcode + i + 1) == 0x81 ||
							*(pcode + i + 1) == 0x82 || *(pcode + i + 1) == 0xa8 || *(pcode + i + 1) == 0xa9 || *(pcode + i + 1) == 0xaa))
						{
							if (*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
								*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //判断一下解密的地址肯定是在尾节.
							{
								decryptsize = 1;
								block2_confirmed = 1;
								
								CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase;
								key1All[numofblock2_trueins] = *(BYTE*)(pcode + i + 6);
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

                        //add word; sub word
                        if (*(pcode + i) == 0x66 && *(pcode + i + 1) == 0x81 && (*(pcode + i + 2) == 0x80 || *(pcode + i + 2) == 0x81 ||
                            *(pcode + i + 2) == 0x82 || *(pcode + i + 2) == 0xa8 || *(pcode + i + 2) == 0xa9 || *(pcode + i + 2) == 0xaa))
                        {
                            if (*(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
                                *(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //判断一下解密的地址肯定是在尾节.
                            {
                                decryptsize = 2;
                                block2_confirmed = 1;

                                CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase;
                                key1All[numofblock2_trueins] = *(WORD*)(pcode + i + 7);
                                const char *damn = "不知道";

                                if ((*(pcode + i + 2) - 0x80 >= 0) && (*(pcode + i + 2) - 0x80) <= 2)
                                {
                                    indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0x80;
                                    methodAll[numofblock2_trueins] = 1;
                                    damn = "加法add";
                                }
                                if ((*(pcode + i + 2) - 0xa8 >= 0) && (*(pcode + i + 2) - 0xa8) <= 2)
                                {
                                    indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0xa8;
                                    methodAll[numofblock2_trueins] = 0;
                                    damn = "减法sub";
                                }
#if DEBUG
                                printf("OEP节尾病毒使用的加密算法为%s, 密钥为%x, 基地址为%x\n", damn, key1All[numofblock2_trueins], CodeEntry2_base_RVAAll[numofblock2_trueins]);
#endif // DEBUG
                                ++numofblock2_trueins;

                            }
                        }

                        //adc byte;sbb byte
                        if (*(pcode + i) == 0x80 && (*(pcode + i + 1) == 0x90 || *(pcode + i + 1) == 0x91 ||
                            *(pcode + i + 1) == 0x92 || *(pcode + i + 1) == 0x98 || *(pcode + i + 1) == 0x99 || *(pcode + i + 1) == 0x9a))
                        {
                            if (*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
                                *(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //判断一下解密的地址肯定是在尾节.
                            {
                                decryptsize = 1;
                                block2_confirmed = 1;

                                CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase;
                                key1All[numofblock2_trueins] = *(BYTE*)(pcode + i + 6);
                                const char *damn = "不知道";

                                if ((*(pcode + i + 1) - 0x90 >= 0) && (*(pcode + i + 1) - 0x90) <= 2)
                                {
                                    indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0x90;
                                    methodAll[numofblock2_trueins] = 4;
                                    damn = "加法adc";
                                }
                                if ((*(pcode + i + 1) - 0x98 >= 0) && (*(pcode + i + 1) - 0x98) <= 2)
                                {
                                    indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0x98;
                                    methodAll[numofblock2_trueins] = 5;
                                    damn = "减法sbb";
                                }
#if DEBUG
                                printf("OEP节尾病毒使用的加密算法为%s, 密钥为%x, 基地址为%x\n", damn, key1All[numofblock2_trueins], CodeEntry2_base_RVAAll[numofblock2_trueins]);
#endif // DEBUG
                                ++numofblock2_trueins;
                            }
                        }

                        //adc word; sbb word
						if (*(pcode + i) == 0x66 && *(pcode + i + 1) == 0x81 && (*(pcode + i + 2) == 0x90 || *(pcode + i + 2) == 0x91 ||
							*(pcode + i + 2) == 0x92 || *(pcode + i + 2) == 0x98 || *(pcode + i + 2) == 0x99 || *(pcode + i + 2) == 0x9a))
						{
							if (*(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
								*(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //判断一下解密的地址肯定是在尾节.
							{
								decryptsize = 2;
								block2_confirmed = 1;
								
								CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 3) - pinh->OptionalHeader.ImageBase;
								key1All[numofblock2_trueins] = *(WORD*)(pcode + i + 7);
								const char *damn = "不知道";

								if ((*(pcode + i + 2) - 0x90 >= 0) && (*(pcode + i + 2) - 0x90) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0x90;
									methodAll[numofblock2_trueins] = 4;
									damn = "加法adc";
								}
								if ((*(pcode + i + 2) - 0x98 >= 0) && (*(pcode + i + 2) - 0x98) <= 2)
								{
									indexAll_Block2[numofblock2_trueins] = *(pcode + i + 2) - 0x98;
									methodAll[numofblock2_trueins] = 5;
									damn = "减法sbb";
								}
#if DEBUG
								printf("OEP节尾病毒使用的加密算法为%s, 密钥为%x, 基地址为%x\n", damn, key1All[numofblock2_trueins], CodeEntry2_base_RVAAll[numofblock2_trueins]);
#endif // DEBUG
								++numofblock2_trueins;

							}
						}

                       
                        //rol dword byte; ror dword byte
                        if (*(pcode + i) == 0xc1 && (*(pcode + i + 1) == 0x80 || *(pcode + i + 1) == 0x81 ||
                            *(pcode + i + 1) == 0x82 || *(pcode + i + 1) == 0x88 || *(pcode + i + 1) == 0x89 || *(pcode + i + 1) == 0x8a))
                        {
                            if (*(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase >= pLastSec->VirtualAddress &&
                                *(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase < pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize)    //判断一下解密的地址肯定是在尾节.
                            {
                                decryptsize = 4;
                                block2_confirmed = 1;

                                CodeEntry2_base_RVAAll[numofblock2_trueins] = *(int*)(pcode + i + 2) - pinh->OptionalHeader.ImageBase;
                                key1All[numofblock2_trueins] = *(BYTE*)(pcode + i + 6);
                                const char *damn = "不知道";

                                if ((*(pcode + i + 1) - 0x80 >= 0) && (*(pcode + i + 1) - 0x80) <= 2)
                                {
                                    indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0x80;
                                    methodAll[numofblock2_trueins] = 2;
                                    damn = "rol";
                                }
                                if ((*(pcode + i + 1) - 0x88 >= 0) && (*(pcode + i + 1) - 0x88) <= 2)
                                {
                                    indexAll_Block2[numofblock2_trueins] = *(pcode + i + 1) - 0x88;
                                    methodAll[numofblock2_trueins] = 3;
                                    damn = "ror";
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
							(*(pcode + i + 1) == 0xe8 || *(pcode + i + 1) == 0xe9 || *(pcode + i + 1) == 0xea))  //sub eax/ecx/edx,4
						{
							index = *(pcode + i + 1) - 0xe8;   //这个用于临时保存第三块的使用的寄存器索引.
							block3_confirmed = 1;
						}

						if (*(pcode + i) == 0x83 && *(pcode + i + 2) == 2 &&
							(*(pcode + i + 1) == 0xe8 || *(pcode + i + 1) == 0xe9 || *(pcode + i + 1) == 0xea))  //sub eax/ecx/edx,2
						{
							index = *(pcode + i + 1) - 0xe8;   //这个用于临时保存第三块的使用的寄存器索引.
							block3_confirmed = 1;
						}

						if (*(pcode + i) == 0x48 || *(pcode + i + 1) == 0x49 || *(pcode + i + 1) == 0x4a)  //dec eax/ecx/edx
						{
							index = *(pcode + i) - 0x48;
							block3_confirmed = 1;
						}

                        if (*(pcode + i) == 0x83 && *(pcode + i + 2) == 0xfc &&                //add eax/ecx/edx,-4
                            (*(pcode + i + 1) == 0xc0 || *(pcode + i + 1) == 0xc1 || *(pcode + i + 1) == 0xc2))
                        {
                            index = *(pcode + i + 1) - 0xc0;   //这个用于临时保存第三块的使用的寄存器索引.
                            block3_confirmed = 1;
                        }





					}

					if (jmptimes == 3 || jmptimes == 4)       //这个block4的confirmed让人有点不大放心, 感觉这个似乎有必要那些jcc全部给他加上, 不过手头的变种又暂时没发现需要的..
					{                                         //或者干脆取消它就完了.
						if (*(pcode + i) == 0x0f && (*(pcode + i + 1) >= 0x80&& *(pcode + i + 1) <= 0x8f))  //长jnb  jge
						{							
							block4_confirmed = 1;
						}
						if (*(pcode + i) >= 0x70 && *(pcode + i) <= 0x7f)   //短jnb jge     //好了, 不管了, 反正我给他全加上了..
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
								printf("所有均已搜完,非virut,退出\n");
								goto end4;
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
								printf("所有均已搜完,非virut,退出\n");
								goto end4;
								
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
								printf("所有均已搜完,非virut,退出\n");
								goto end4;
								
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
								
								printf("所有均已搜完,非virut,退出\n");
								goto end4;
														
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
								printf("所有均已搜完,非virut,退出\n");
								goto end4;
								
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
								printf("所有均已搜完,非virut,退出\n");
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
							printf("解析oep节节尾跳转出错\n");
#endif // DEBUG
							if (oepsearchpos < oepremainbytes - 0x10)
							{
								printf("可能是hook点1选错,从上次搜到E9的位置后面继续搜索\n");
								goto research_hook1;
							}
							printf("所有均已搜完,非virut,退出\n");
							goto end4;
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
						printf("所有均已搜完,非virut,退出\n");
						goto end4;
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
					printf("所有均已搜完,非virut,退出\n");
					goto end4;
				}

			}

			
oepvir_decode:

			if (decryptsize == 0)
			{
#if DEBUG
				printf("未知解密方式,退出\n");
				goto end4;
#endif
			}

			CodeEntry1_Base_RVA = block_RVA[0];
			for (int j = 0; block_RVA[j] != 0; ++j)
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

			//0 add 1 sub 2 rol 3 ror 4 adc 5 sbb

			DWORD *pTemp = (DWORD*)(data + RVA2FO(pish, numOfSections, CodeEntry2_base_RVA));
            BOOL cf = 0;
			for (int i = CodeEntry2_base_size / decryptsize; i >= 0 ; --i)  //CodeEntry2_base_size 为以decryptsize为单位的数目, 所以这里不需要除以decryptsize
			{
				if (decryptsize == 1)
				{
                    if (method == 0 || method == 1)
                    {
                        *((BYTE*)pTemp + i ) = method == 1 ? *((BYTE*)pTemp + i) + LOBYTE(key1) : *((BYTE*)pTemp + i) - LOBYTE(key1);
                    }
                    
                    if (method == 2 || method == 3)
                    {
                        *((BYTE*)pTemp + i) = method == 2 ? rol(*((BYTE*)pTemp + i), key1) : ror(*((BYTE*)pTemp + i), key1);
                    }

                    if (method == 4)
                    {
                        BYTE tempbyte = *((BYTE*)pTemp + i);
                        *((BYTE*)pTemp + i) = *((BYTE*)pTemp + i) + LOBYTE(key1) + cf;
                        cf = getCFbyte(tempbyte, LOBYTE(key1), cf);
                    }

                    if (method == 5)
                    {
                        BYTE tempbyte = *((BYTE*)pTemp + i);
                        *((BYTE*)pTemp + i) = *((BYTE*)pTemp + i) - LOBYTE(key1) - cf;
                        cf = getCFbyte_sbb(tempbyte, LOBYTE(key1), cf);
                    }

                    			
				}
				if (decryptsize == 2)
				{
					if (method == 1 || method == 0)
					{
						*((WORD*)pTemp + i) = method ? *((WORD*)pTemp + i) + LOWORD(key1) : *((WORD*)pTemp + i) - LOWORD(key1);
					}

                    if (method == 2 || method == 3)
                    {
                        *((WORD*)pTemp + i) = method == 2 ? rol(*((WORD*)pTemp + i), key1) : ror(*((WORD*)pTemp + i), key1);
                    }

                    if (method == 4)
                    {
                        WORD tempword = *((WORD*)pTemp + i);
                        *((WORD*)pTemp + i) = *((WORD*)pTemp + i) + LOWORD(key1) + cf;
                        cf = getCFword(tempword + cf, LOWORD(key1), cf);
                    }

                    if (method == 5)
                    {
                        WORD tempword = *((WORD*)pTemp + i);
                        *((WORD*)pTemp + i) = *((WORD*)pTemp + i) - LOWORD(key1) - cf;
                        cf = getCFword_sbb(tempword, LOBYTE(key1), cf);
                    }

				}
				if (decryptsize == 4)
				{
					if (method == 1 || method == 0)
					{
						*((DWORD*)pTemp + i) = method ? *((DWORD*)pTemp + i) + key1 : *((DWORD*)pTemp + i) - key1;
					}

                    if (method == 2 || method == 3)
                    {
                        *((DWORD*)pTemp + i) = method == 2 ? rol(*((DWORD*)pTemp + i), key1) : ror(*((DWORD*)pTemp + i), key1);
                    }
                    
                    if (method == 4)
                    {
                        DWORD tempdword = *((DWORD*)pTemp + i);
                        *((DWORD*)pTemp + i) = *((DWORD*)pTemp + i) + key1 + cf;
                        cf = getCFdword(tempdword + cf, key1, cf);
                    }

                    if (method == 5)
                    {
                        DWORD tempdword = *((DWORD*)pTemp + i);
                        *((DWORD*)pTemp + i) = *((DWORD*)pTemp + i) - key1 - cf;
                        cf = getCFdword_sbb(tempdword + cf, key1, cf);
                    }

				}
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
            int times =  0;
			BOOL findlast = FALSE;
			int backvalue1 = 0, backvalue2 = 0;
			int sig_confirmed1 = 0, sig_confirmed2 = 0;   //4个检查差不多够了.
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
				
				for (int i = 0; i < 0x30 * 0xf; )  //根据概率, 绝对够用了.
				{
                    //先验证标志, 然后再看跳不跳.. 这样跳跃也能够作为标志.
					for (int j = 0; j < FuckedVirut[virutkind].num_waypoint; ++j)
					{
						if (FuckedVirut[virutkind].mypath[j].nume8call == num_e8call)  //找到当前的e8call
						{
							for (int k = 0; k < FuckedVirut[virutkind].mypath[j].num_confirmed_sig; ++k)
							{
								if (sig_cmp(pLastCode + i, FuckedVirut[virutkind].mypath[j].confirmed_sig[k]))
								{
									lastsec_sig_confirmed[FuckedVirut[virutkind].mypath[j].confirmed_sig_index[k]] = 1;
								}
							}

							if (FuckedVirut[virutkind].mypath[j].times) //用于确认有需要碰到指定次数就跳的指令.
							{
								for (int k = 0; k < 2; ++k)
								{
									if (sig_cmp(pLastCode + i, FuckedVirut[virutkind].mypath[j].sig[k]))
									{
										++times;
										if (times == FuckedVirut[virutkind].mypath[j].times)
										{
                                         
											if (FuckedVirut[virutkind].mypath[j].size_jmpvalue[k] == 1)  //要么是1, 要么是4
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

                            

							break;  //确认完了就直接break; 不需要继续循环了, 因为num_e8call是唯一的.

						}// end of xxx == nume8call
					}

                    if (FuckedVirut[virutkind].bjmpback == TRUE && num_e8call == 1)
                    {
                        if (sig_cmp(pLastCode + i, FuckedVirut[virutkind].jmpbackins))
                        {
                            nextRVA = backvalue1 - pinh->OptionalHeader.ImageBase;
                            goto nextpos;
                        }
                    }


					if (num_e8call == FuckedVirut[virutkind].lastnume8call && *(pLastCode + i) == 0xc3)
					{
						if (FuckedVirut[virutkind].bHasInstructionBeforeJmpBody == FALSE) //此时e9/eb就是直接跟着的
						{
							if (*(pLastCode + i + 5) == 0xeb)
							{
								bodybase_RVA = prevRVA + i + 5 + 2 + *(int8_t*)(pLastCode + i + 5 + 1);  //算出跳转的目的地址
#if DEBUG
								printf("尾节最终block块RVA为%x\n", bodybase_RVA);
#endif // DEBUG
								goto outofwhile;
							}

							if (*(pLastCode + i + 5) == 0xe9)
							{
								bodybase_RVA = prevRVA + i + 5 + 5 + *(int*)(pLastCode + i + 5 + 1);
#if DEBUG
								printf("尾节最终block块RVA为%x\n", bodybase_RVA);
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
						//此时eb或e9肯定就跟着的.
						if (*(pLastCode + i + FuckedVirut[virutkind].LastInstructionSize) == 0xeb)
						{
							bodybase_RVA = prevRVA + i + FuckedVirut[virutkind].LastInstructionSize + 2
								+ *(int8_t*)(pLastCode + i + FuckedVirut[virutkind].LastInstructionSize + 1);  //算出跳转的目的地址
#if DEBUG
							printf("尾节最终block块RVA为%x\n", bodybase_RVA);
#endif // DEBUG
							goto outofwhile;
						}

						if (*(pLastCode + i + FuckedVirut[virutkind].LastInstructionSize) == 0xe9)
						{
							bodybase_RVA = prevRVA + i + FuckedVirut[virutkind].LastInstructionSize + 5
								+ *(int*)(pLastCode + i + FuckedVirut[virutkind].LastInstructionSize + 1);
#if DEBUG
							printf("尾节最终block块RVA为%x\n", bodybase_RVA);
#endif // DEBUG
							goto outofwhile;
						}
					}

					if (sig_cmp(pLastCode + i, "e8"))
					{
						++num_e8call;
                        times = 0; // 经过call就把这个计数给重置了..
						for (int j = 0; j < FuckedVirut[virutkind].num_waypoint; ++j)
						{
							if (FuckedVirut[virutkind].mypath[j].nume8call == num_e8call)
							{
								//先检查是否产生backvalue1再检查是否跟进
								if (FuckedVirut[virutkind].mypath[j].bGenBackValue1)
								{
									backvalue1 = i + 5 + prevRVA + pinh->OptionalHeader.ImageBase;
#if DEBUG
									printf("用于计算回跳点的值1:%x\n", backvalue1);
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
								//此时就需要验证相应的confirmed是否为1
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
										printf("非变种%d,换种方式\n", virutkind);
#endif
										++virutkind;
										goto refuck;
									}
#if DEBUG
									printf("可能不是virut样本,退出\n");
#endif
									goto end4;
								}
							}
							else
							{
								break; //如果这里小于,那么后续的也就会小于,那么就没必要循环了.
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
						if (i >= 0x30*0xf)  //靠, 就因为这个我找了半天..org
						{
							if (virutkind < MAXKIND)
							{
#if DEBUG
								printf("非变种%d,换种方式\n", virutkind);
#endif
								++virutkind;
								goto refuck;
							}
#if DEBUG
							printf("可能不是virut样本,退出\n");
#endif
							goto end4;
						}
					}
					else
					{
                       
						if (virutkind < MAXKIND)
						{
#if DEBUG
							printf("非变种%d,换种方式\n", virutkind);
#endif
							++virutkind;
							goto refuck;
						}
#if DEBUG
						printf("可能不是virut样本,退出\n");
#endif
						goto end4;
					}
				}
nextpos:			
				pLastCode = data + RVA2FO(pish, numOfSections, nextRVA);
				prevRVA = nextRVA;
				++jmptimes;
				if (jmptimes >= 0x100)        //0x100块够用了..
				{
					if (virutkind < MAXKIND)
					{
#if DEBUG
						printf("跳转次数过多,出现死循环,非变种%d,换种方式\n", virutkind);
#endif
						++virutkind;
						goto refuck;
					}
#if DEBUG
					printf("跳转次数过多,出现死循环, 可能不是virut样本,退出\n");
#endif
					goto end4;
				}
			}//end of while(1)

            
		outofwhile:

			
            //现在bodybase_RVA有了, 准备用各种偏移上的数据爆破出算法的密钥.

			WORD keyfull = 0;
            PBLOCKDESCRIPTOR pBlock = (PBLOCKDESCRIPTOR)(data + RVA2FO(pish, numOfSections, bodybase_RVA) + BLOCKOFF_MIN);
            BOOL found = FALSE;

			for(int bj = last_crack_method, bm = 2; bm--; bj = (++bj) % 2)
			{
				if (bj == 0)
				{
					for (int p = last_before_sig, c = num_sig; c--; p = (++p) % num_sig)  //这样就从last_before_sig开始循环, 并保证了每个元素都会循环到一次
					{
						for (int k = last_before_off_index, m = num_off; m--; k = (++k) % num_off)  //同理
						{
							BYTE* db_base_x_after = data + RVA2FO(pish, numOfSections, bodybase_RVA) + before_off_array[k];

							char str_after[0x200] = { 0 };

							for (int b = 0; b < before_len[p]; ++b)
							{
								if (before_sig[p][b] != 0x11)
								{
									sprintf_s(str_after, "%s %02x", str_after, db_base_x_after[b]);
								}
								else
								{
									sprintf_s(str_after, "%s %s", str_after, "??");
								}
							}


							for (DWORD i = 0; i <= 0xffff; ++i)   //防止死循环.
							{
								BYTE db_before[0x20] = { 0 };
								memcpy(db_before, before_sig[p], 0x20);

								FuckedVirut[virutkind].EncryptFunc(db_before, i, FuckedVirut[virutkind].dw_key_sig, 0x20);

								if (sig_cmp(db_before, str_after))
								{
									found = TRUE;
									//说明找到了
									keyfull = i;

									last_before_off_index = k;
									last_before_off = before_off_array[k];
									last_before_sig = p;
									last_crack_method = 0;

									goto outofcrack;
								}
							}
						}
					}
				}
				
				if (bj == 1)
				{
					for (int p = last_before_sig, c = num_sig; c--; p = (++p) % num_sig)
					{
						for (int k = last_before_off, j = 0x200; j--; k = (++k) % 0x200)  //根据观察, 标志基本在0x200范围内, 所以就全来一遍
						{
							BYTE* db_base_x_after = data + RVA2FO(pish, numOfSections, bodybase_RVA) + k;

							char str_after[0x200] = { 0 };

							for (int b = 0; b < before_len[p]; ++b)
							{
								if (before_sig[p][b] != 0x11)
								{
									sprintf_s(str_after, "%s %02x", str_after, db_base_x_after[b]);
								}
								else
								{
									sprintf_s(str_after, "%s %s", str_after, "??");
								}
							}

							for (DWORD i = 0; i <= 0xffff; ++i)   //防止死循环.
							{
								BYTE db_before[0x20] = { 0 };
								memcpy(db_before, before_sig[p], 0x20);

								FuckedVirut[virutkind].EncryptFunc(db_before, i, FuckedVirut[virutkind].dw_key_sig, 0x20);

								if (sig_cmp(db_before, str_after))
								{
									found = TRUE;
									//说明找到了
									keyfull = i;

									last_before_off = k;
									last_before_sig = p;
									last_crack_method = 1;

									goto outofcrack;
								}
							}
						}
					}
				}
			}

            
			
			
			

outofcrack:
            if (found == FALSE)
            {
#if DEBUG
                printf("爆破密钥出错,退出\n");
#endif
                goto end4;
            }
            


            //这边开始滑动匹配来得到block的偏移..
            //首先, 根据这么多样本的观察, 可以发现block基本在body+0x500~body+0x600之间, 其次, block的大小基本为0x400~0x800之间.
            //所以, 我先从body+0x500开始解密0x800个字节大小


            //算出body+BLOCKOFF_MIN处的keyfull
            //算出body+BLOCKOFF_MIN时的keyfull, 目前是body+last_before_off

            FuckedVirut[virutkind].UpdateKey(&keyfull, FuckedVirut[virutkind].dw_key_sig, BLOCKOFF_MIN - last_before_off);

            //从BLOCKOFF_MIN开始解密BLOCKSIZE_MAX个字节

            FuckedVirut[virutkind].DecryptFunc((BYTE*)pBlock, keyfull, FuckedVirut[virutkind].dw_key_sig, BLOCKSIZE_MAX);

            //解密完毕, 开始滑动匹配找到block的开始位置
            
            for (int i = 0; i < 0x100; ++i)  //从0x500字节开始一个字节一个字节往后匹配
            {
                PBLOCKDESCRIPTOR pTemp = (PBLOCKDESCRIPTOR)((PBYTE)pBlock + i);
                PBLOCKDESCRIPTOR pNext = pTemp + 1;

                if (pTemp->before_bytes != 0 && (pTemp->before_offset + pTemp->before_bytes) == pNext->before_offset
                    && pTemp->before_offset == 0)
                {
					found = TRUE;
                    //此时找到的就应该是第一个blockdescriptor, 保存
                    pBlock = pTemp;
					break;
                }

            }

			if (found == FALSE)
			{
#if DEBUG
				printf("滑动匹配block起始位置出错,退出\n");
#endif
				goto end4;
			}


			//解密完毕, 找到CodeEntry2_Base_RVA


			//WORD* pBodyBlock = (WORD*)(pBlock + 1 + (*pBlock - 1) * 0x8); //找到body的block  //发现解密后的这个blocknum有问题, 还是手动去找算了..

            PBLOCKDESCRIPTOR pBodyBlock = NULL;
			for (int i = 0; i < BLOCKNUM_MAX; ++i)         //0x100个分块上限应该够用了.. 最低的变种是两块.
			{
                if (pBlock[i].before_bytes >= BODYSIZE_MIN && pBlock[i].before_bytes <= BODYSIZE_MAX &&
                    pBlock[i].before_bytes == (pBlock[i].after_bytes & 0x7fff))
                {
                    pBodyBlock = &pBlock[i];
					break;
                }
			}
			if (pBodyBlock == NULL || pBodyBlock->before_offset < 0x100)   //body的beforeoffset, 目前看到两个: 0x1e8, 和 0x300  第三个: 半新代0x2B8..
			{
#if DEBUG
				printf("body的beforeoffset有问题, 可能是body的解密算法出错\n");
#endif // DEBUG

				goto end4;
			}

			CodeEntry2_base_RVA = bodybase_RVA - pBodyBlock->after_offset;

			//如果是通过设置入口点方式的话, 那么就不会有那两条指令... c6 05和c7 05, 所以只有当有HOOK时才去搜这两条指令
			if (hasHook1 == TRUE)
			{
				DWORD CodeToSearch_RVA = 0;
                DWORD SearchBytes = 0;

                //寻找包含recover指令的那个块RVA
				for (int i = 0; i < BLOCKNUM_MAX; ++i)   //0x100块
				{
                    PBLOCKDESCRIPTOR pTemp = pBlock + i;
				
					if ((FuckedVirut[virutkind].recover_off >= pTemp->before_offset) 
                        && (FuckedVirut[virutkind].recover_off < (pTemp->before_bytes + pTemp->before_offset)))
					{
						CodeToSearch_RVA = CodeEntry2_base_RVA + pTemp->after_offset;
                        SearchBytes = pTemp->after_bytes;
#if DEBUG
						printf("包含那两条恢复指令的病毒代码块RVA为%x\n", CodeToSearch_RVA);
#endif // DEBUG
						break;
					}
				}

				BYTE *pSearch = data + RVA2FO(pish, numOfSections, CodeToSearch_RVA);
				DWORD Recover1_VA, Recover2_VA;
				BYTE Recover1_Value;
				DWORD Recover2_Value;
				BOOL b1find = FALSE, b2find = FALSE;

				for (int i = 0; i<SearchBytes; )   //在d7366c5e, 发现了奇葩的block_descript  我这边就直接0x1000个字节
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
						if (i >= 0x1000)
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
			//所以当没有hook1点时, 因为没有那两条c6 05 ; c7 05
			//所以就寻找代码中的backvalue1, 和backvalue2, 然后根据对应的算法来获得最终的oep值.

			if (hasHook1 == FALSE)
			{
				DWORD CodeToSearch_RVA = 0;
                DWORD SearchBytes = 0;

                //接下来寻找包含backvalue2指令的block 
                for (int i = 0; i < BLOCKNUM_MAX; ++i)  
                {
                    PBLOCKDESCRIPTOR pTemp = pBlock + i;

                    if ((FuckedVirut[virutkind].backvalue_off >= pTemp->before_offset)
                        && (FuckedVirut[virutkind].backvalue_off < (pTemp->before_bytes + pTemp->before_offset)))
                    {
                        CodeToSearch_RVA = CodeEntry2_base_RVA + pTemp->after_offset;
                        SearchBytes = pTemp->after_bytes;
#if DEBUG
                        printf("包含那两条恢复指令的病毒代码块RVA为%x\n", CodeToSearch_RVA);
#endif // DEBUG
                        break;
                    }
                }
				
				if (CodeToSearch_RVA)
				{
					BYTE *pSearch = data + RVA2FO(pish, numOfSections, CodeToSearch_RVA);
					for (int i = 0; i < SearchBytes; )   //在c73a190a  的80cd出错, 所以扩大. 然而发现其实是因为反汇编出错导致的出错..
					{  //有些独特的, 得分开.
						if (virutkind == 3)
						{
							if (sig_cmp(pSearch + i, "81 cd"))   //这里有个81 CD xx xx xx xx   or      ebp, 0FFFFDC91h
							{
								backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
							}

							if (sig_cmp(pSearch + i, "01 6b f8"))  // add     [ebx-8], ebp  //加法  //目前就看到这种, 不过我就把剩下的两种写了
							{
								calc_backupvaluemethod = 1;
								break;
							}
							if (sig_cmp(pSearch + i, "31 6b f8"))  // xor     [ebx-8], ebp  //异或
							{
								calc_backupvaluemethod = 2;
								break;
							}
							if (sig_cmp(pSearch + i, "29 6b f8"))  // sub     [ebx-8], ebp  //减法
							{
								calc_backupvaluemethod = 3;
								break;
							}
						}else if (virutkind == 8 || virutkind == 0xa|| virutkind == 0xf || virutkind == 0x10 
                            || virutkind == 0x16 || virutkind == 0x17 || virutkind == 0x18 || virutkind == 0x19 
                            || virutkind == 0x1b || virutkind == 0x1c || virutkind == 0x1d || virutkind == 0x1e
                            || virutkind == 0x1f)
						{
							if (sig_cmp(pSearch + i, "bd"))   //mov ebp, dd_backvalue2
							{
								backvalue2 = *(int*)(pSearch + i + 1);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                calc_backupvaluemethod = 1;
                                break;
							}
							
                        }
                        else if (virutkind == 6 || virutkind == 9)
                        {
                            if (sig_cmp(pSearch + i, "81 f5"))   //xor ebp, dd_backvalue2
                            {
                                calc_backupvaluemethod = 1;
                                backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }
                        }
                        else if (virutkind == 0xb || virutkind == 0xc || virutkind == 0xd || virutkind == 0xe 
                            || virutkind == 0x11 || virutkind == 0x1a || virutkind == 0x22 || virutkind == 0x23
                            || virutkind == 0x24 || virutkind == 0x25)
                        {
                            if (sig_cmp(pSearch + i, "81 ed"))
                            {
                                calc_backupvaluemethod = 1;       
                                backvalue2 = 0 - *(int*)(pSearch + i + 2);
                                backvalue1 = 0;        //这个变种很心机啊, 居然把backvalue1清零了..
#if DEBUG                       
                                printf("特别的变种,用于计算回跳点的值1:%x\n", backvalue1); //注意,这一行别写在#if DEBUG这行上了.
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }
                            if (sig_cmp(pSearch + i, "81 c5"))
                            {
                                calc_backupvaluemethod = 1;
                                backvalue2 = *(int*)(pSearch + i + 2);
                                backvalue1 = 0;        //这个变种很心机啊, 居然把backvalue1清零了..
#if DEBUG                       
                                printf("特别的变种,用于计算回跳点的值1:%x\n", backvalue1); //注意,这一行别写在#if DEBUG这行上了.
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }


                        }else if (virutkind == 0x12)
                        {
                            if (sig_cmp(pSearch + i, "c7 43 14"))   // mov [ebx+0x14], oep_va
                            {
                                backvalue1 = 0;
                                backvalue2 = *(int*)(pSearch + i + 3);
                                calc_backupvaluemethod = 1;
                                break;
                            }
                        }else if (virutkind == 0x13)
                        {
                            if (sig_cmp(pSearch + i, "81 6c 24 24"))   //sub dword ptr [esp+0x24], dd_backvalue2
                            {
                                calc_backupvaluemethod = 3;
                                backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }
                        }
                        else if (virutkind == 0x14 || virutkind == 0x15)
                        {
                            if (sig_cmp(pSearch + i, "81 6B 13"))  // sub dword ptr [ebx+13h],backvalue2
                            {
                                calc_backupvaluemethod = 3;
                                backvalue2 = *(int*)(pSearch + i + 3);
#if DEBUG
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }
                        }else if (virutkind == 0x20 || virutkind == 0x22 || virutkind == 0x28)
                        {
                            if (sig_cmp(pSearch + i, "68"))
                            {
                                calc_backupvaluemethod = 1;
                                backvalue2 = *(int*)(pSearch + i + 1);
                                backvalue1 = 0;
#if DEBUG
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }
                        }else if (virutkind == 0x21 || virutkind == 0x2a)
                        {
                            if (sig_cmp(pSearch + i, "bd"))
                            {
                                calc_backupvaluemethod = 1;
                                backvalue2 = *(int*)(pSearch + i + 1);
                                backvalue1 = 0;
#if DEBUG
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }
                        }
                        else if (virutkind == 0x26 || virutkind == 0x27)
                        {
                            if (sig_cmp(pSearch + i, "05"))  // add eax,dd_backvalue2
                            {
                                calc_backupvaluemethod = 1;
                                backvalue2 = *(int*)(pSearch + i + 1);
                                backvalue1 = 0;
#if DEBUG
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }
                        }else if (virutkind == 0x2b)
                        {
							if (sig_cmp(pSearch + i, "C7 44 24 20"))  // add [esp+20h],dd_backvalue2
							{
								calc_backupvaluemethod = 1;
								backvalue2 = *(int*)(pSearch + i + 4);
								backvalue1 = 0;
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
								break;
							}
                        }
						else
						{
							if (sig_cmp(pSearch + i, "81 44 24 24"))   //add dword ptr [esp+0x24], dd_backvalue2  目前我就看到第一种的, 顺便把后两种给补了..  //还有 esp+0x20的. 于是我直接去了+xx的偏移
							{
								calc_backupvaluemethod = 1;
								backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 74 24 24"))   //xor dword ptr [esp+0x24], dd_backvalue2
							{
								calc_backupvaluemethod = 2;
								backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
								break;
							}

                            if (sig_cmp(pSearch + i, "81 6c 24 24"))   //sub dword ptr [esp+0x24], dd_backvalue2
                            {
                                calc_backupvaluemethod = 3;
                                backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }

							

							if (sig_cmp(pSearch + i, "81 c5"))  //add ebp, dd_backvalue2    目前变种4基准就看到这个, 我顺便把下面两种方式给写了.
							{                                   // 0x29变种
								calc_backupvaluemethod = 1;
								backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 f5"))  //xor ebp, dd_backvalue2   
							{
								calc_backupvaluemethod = 2;
								backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 ed"))  //sub ebp, dd_backvalue2   
							{
								calc_backupvaluemethod = 3;
								backvalue2 = *(int*)(pSearch + i + 2);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
								break;
							}
						}
						

						int count = cs_disasm(handle, pSearch + i, 0xf, 0, 1, &insn);
						if (count == 1)
						{
							i += insn[0].size;
							cs_free(insn, count);
							if (i >= 0x1000)
							{
#if DEBUG
								printf("找backvalue2指令位置出错\n");
#endif // DEBUG
								goto end4;
							}
						}
						else
						{
                            if (i < 0x1000) //在c73a190a的80cd 样本, 反汇编指令出错, 所以加了个这个
                            {
                                i += 1;
#if DEBUG
                                printf("找backvalue2指令时反汇编出错,跳过该字节\n");
#endif // DEBUG
                                continue;
                            }



#if DEBUG
							printf("找backvalue2指令位置出错\n");
#endif // DEBUG
							goto end4;
						}
					}
				}


				//这时候通过两个块来计算出原oep值
				//尾节开始代码的的e9 xx 00 00 00 00			

                //现在下面这三个没什么意义了, 我后面那些变种, 基本都设成1,然后修改backvalue1的值为0了..
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
					printf("入口节节尾病毒数据覆盖至下一区段, 本文件可能已经永久损坏\n");
					goto end4;
#endif
				}
				memset((BYTE*)(data + pOepSec->PointerToRawData + pOepSec->Misc.VirtualSize), 0, OEPSectionReduce_VSize);

#if DEBUG
				printf("将OEP区段表的VSize减小%x\n", OEPSectionReduce_VSize);
				printf("将OEP区段的raddr: %x处的%x字节清0\n", pOepSec->PointerToRawData + pOepSec->Misc.VirtualSize, OEPSectionReduce_VSize);
#endif // DEBUG


			}

			//清除感染标记     //感染标记还是不清比较好, 这样就像是打了个疫苗, 有了抗体..
            /*if (virutkind == 1)
            {
                *(DWORD*)(data + 0x20) = 0;
            }else if (virutkind == 8)
            {
                *(DWORD*)(data + 0x24) = 0;
            }
            else
            {
                pinh->FileHeader.TimeDateStamp = 0;
            }*/
			
            success = TRUE;

		} // end of if codeentry2

	}

#if DEBUG
	if (virutkind == 0)
	{
		printf("确认非virut变种,不处理\n");
	}
#endif // DEBUG

end4:

    if (success)
    {
#if DEBUG
        printf("修复成功,开始写入数据\n");
#endif
        DWORD byteswritten = 0;
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        WriteFile(hFile, data, dwFileSize, &byteswritten, NULL);
        if (byteswritten != dwFileSize)
        {
#if DEBUG
            printf("修复后的数据写入失败\n");
#endif
        }
        else
        {
#if DEBUG
            printf("文件修复成功\n");
#endif
            SetFilePointer(hFile, dwFileSize, NULL, FILE_BEGIN);
            SetEndOfFile(hFile);
            
        }
    }


    VirtualFree(data, NULL, MEM_DECOMMIT|MEM_RELEASE);

end3:

    ;

end2:


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
        printf("修复文件%s\n", data.cFileName);
        ScanFile(cFullPath, FALSE);
        printf("\n\n");
    } while (FindNextFile(hFind, &data));

    FindClose(hFind);

	return 0;
}