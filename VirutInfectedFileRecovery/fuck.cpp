//fucked by baoshijin
//last modified date: 2019.1.9



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



//-1 代表未知
//0  代表不是
//1  代表旧一代0x1e8 0x3d34  有微变变种
//2  代表新一代0x300 0x66e4  有微变变种
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
#if MYTEST
			PIMAGE_SECTION_HEADER pjunk = &pish[pinh->FileHeader.NumberOfSections - 1];
			char tempname[8] = { 0 };
			memcpy(tempname, pjunk->Name, 8);
			
			if (checksecname(tempname))
			{
				if (pjunk->Misc.VirtualSize == 0x1000 && pjunk->Characteristics == 0xc000'0000 && pjunk->SizeOfRawData == 0)
				{
					virutkind = 2;
					printf("可能为已知变种2或4, 开始进行处理\n");

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
			DWORD block_RVA[5+1] = { 0 };  //尾部的0作为一个标记
			int block1_confirmed = 0, block2_confirmed, block3_confirmed, block4_confirmed;
			int index = -1;
			int indexAll[10] = { 0 };
			DWORD key1 = 0;
			DWORD key1All[10] = { 0 };
			int method = -1; //1表示add, 0表示sub  初始为-1,这样出现意外情况时,使其出错
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

						if (*(pcode + i) == 0x48 || *(pcode + i + 1) == 0x49 || *(pcode + i + 1) == 0x4a)
						{
							index = *(pcode + i) - 0x48;
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
						if (i >= 0x100)
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

			// 现在bodybase_RVA有了, 准备去解密bodybase_RVA+0x53c处的数据
			//+539 00 c3  利用这两个数据, 利用加密算法的漏洞算出key, 
			WORD keyfull;
			BYTE* pBlock = data + RVA2FO(pish, numOfSections, bodybase_RVA) + 0;  

            BYTE* db_base_x_after = data + RVA2FO(pish, numOfSections, bodybase_RVA) + FuckedVirut[virutkind].db_before_sig_offset_from_body;

            pBlock = pBlock + FuckedVirut[virutkind].block_descript_offset - 1;
            BOOL found = FALSE;

            for (DWORD i = 0; i <= 0xffff; ++i)   //这里用DWORD而不是word是为了防止0ffff执行后++i,又变成0, 成了死循环.
            {
                BYTE db_before[0x10] = { 0 };
                memcpy(db_before, FuckedVirut[virutkind].db_before_sig, FuckedVirut[virutkind].db_before_sig_len);
                int temp = i;

                FuckedVirut[virutkind].EncryptFunc(db_before, i, FuckedVirut[virutkind].dw_key_sig, FuckedVirut[virutkind].db_before_sig_len);

                if (!memcmp(db_base_x_after, db_before, FuckedVirut[virutkind].db_before_sig_len))
                {
                    found = TRUE;
                    //说明找到了
                    keyfull = i;
                    break;
                }
            }

            if (found == FALSE)
            {
#if DEBUG
                printf("爆破密钥出错,退出\n");
#endif
                goto end4;
            }

            //然后算出body+ block偏移 - 1时的keyfull

            FuckedVirut[virutkind].UpdateKey(&keyfull, FuckedVirut[virutkind].dw_key_sig, FuckedVirut[virutkind].block_descript_offset - 1 - FuckedVirut[virutkind].db_before_sig_offset_from_body);

            //从blockdescript-1开始解密

            FuckedVirut[virutkind].DecryptFunc(pBlock, keyfull, FuckedVirut[virutkind].dw_key_sig, FuckedVirut[virutkind].block_descript_size + 1);

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
			if (pBodyBlock == NULL || *(pBodyBlock + 1) < 0x100)   //body的beforeoffset, 目前看到两个: 0x1e8, 和 0x300  第三个: 半新代0x2B8..
			{
#if DEBUG
				printf("body的beforeoffset有问题, 可能是body的解密算法出错\n");
#endif // DEBUG

				goto end4;
			}

			CodeEntry2_base_RVA = bodybase_RVA - *(pBodyBlock + 2);

			//如果是通过设置入口点方式的话, 那么就不会有那两条指令... c6 05和c7 05, 所以只有当有HOOK时才去搜这两条指令
			if (hasHook1 == TRUE)
			{
				DWORD CodeToSearch_RVA = 0;
				//接下来寻找包含before_offset 173的block
				//新一代中是包含before_offset b4的block 
				//半新代是包含before_offset c2的block
				//virutkind==4是找b5的块
				for (int i = 0; i < 0x100; ++i)
				{
					PWORD pTemp = (PWORD)(pBlock + 1 + i * 8);
				
					if ((FuckedVirut[virutkind].recover_off >= *(pTemp + 1)) && (FuckedVirut[virutkind].recover_off < (*(pTemp + 1) + *pTemp)))
					{
						CodeToSearch_RVA = CodeEntry2_base_RVA + *(pTemp + 2);

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
			//所以当没有hook1点时, 因为没有那两条c6 05 ; c7 05
			//所以就寻找代码中的backvalue1, 和backvalue2, 然后根据对应的算法来获得最终的oep值.

			if (hasHook1 == FALSE)
			{
				DWORD CodeToSearch_RVA = 0;
					
                //接下来寻找包含backvalue2指令的block 
                for (int i = 0; i < 0x100; ++i)
                {
                    PWORD pTemp = (PWORD)(pBlock + 1 + i * 8);

                    if ((FuckedVirut[virutkind].backvalue_off >= *(pTemp + 1)) && (FuckedVirut[virutkind].backvalue_off < (*(pTemp + 1) + *pTemp)))
                    {
                        CodeToSearch_RVA = CodeEntry2_base_RVA + *(pTemp + 2);
#if DEBUG
                        printf("包含backvalue2指令的病毒代码块RVA为%x\n", CodeToSearch_RVA);
#endif // DEBUG
                        break;
                    }
                }
				
				if (CodeToSearch_RVA)
				{
					BYTE *pSearch = data + RVA2FO(pish, numOfSections, CodeToSearch_RVA);
					for (int i = 0; i < 0x100; )
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
						}else if (virutkind == 8)
						{
							if (sig_cmp(pSearch + i, "bd"))   //mov ebp, dd_backvalue2
							{
								backvalue2 = *(int*)(pSearch + i + 1);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
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
								printf("用于计算回跳点的值2:%x\n", backvalue2);
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
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
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
                                calc_backupvaluemethod = 1;       //这变种居然把那个放外面去了..
                                backvalue2 = *(int*)(pSearch + i + 1);
#if DEBUG
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
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
                                backvalue1 = 0;        //这个变种很心机啊, 居然把backvalue1清零了..
#if DEBUG                       
                                printf("特别的变种,用于计算回跳点的值1:%x\n", backvalue1); //注意,这一行别写在#if DEBUG这行上了.
                                printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
                                break;
                            }
                        }
						else
						{
							if (sig_cmp(pSearch + i, "81 44 24"))   //add dword ptr [esp+0x24], dd_backvalue2  目前我就看到第一种的, 顺便把后两种给补了..  //还有 esp+0x20的. 于是我直接去了+xx的偏移
							{
								calc_backupvaluemethod = 1;
								backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 74 24"))   //xor dword ptr [esp+0x24], dd_backvalue2
							{
								calc_backupvaluemethod = 2;
								backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 6c 24"))   //sub dword ptr [esp+0x24], dd_backvalue2
							{
								calc_backupvaluemethod = 3;
								backvalue2 = *(int*)(pSearch + i + 4);
#if DEBUG
								printf("用于计算回跳点的值2:%x\n", backvalue2);
#endif
								break;
							}

							if (sig_cmp(pSearch + i, "81 c5"))  //add ebp, dd_backvalue2    目前变种4基准就看到这个, 我顺便把下面两种方式给写了.
							{
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

			//清除感染标记
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


	return 0;
}