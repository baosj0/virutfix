#include "../../Include/pub.h"
#include "../../Include/EXEPE.h"
#include "../../kv0000/Base/PE.h"

/*
最新变种：在每一个感染的文件后面增加了一个空节，节名7个小写字母随机。
#   Name      VirtSize    RVA     PhysSize  Phys off  Flags
--  --------  --------  --------  --------  --------  --------
01  .text     00001CEE  00001000  00001E00  00000400  E0000020 [CERW]
02  .data     00002330  00003000  00000200  00002200  C0000040 [IRW]
03  .rsrc     00007A00  00006000  00007600  00002400  E0000060 [CEIRW]
04  lctgqpf   00001000  0000E000  00000000  00009A00  C0000000 [RW]

最后一个节 --> 倒数第二个节

感染方式：
1、入口在感染节，解读办法就是找到并还原真正入口，然后截断病毒体；
----------------------------------------------------------------------------------------------------



2、入口不变，某些指令替换长跳转。恢复原始指令（5字节），然后截断病毒体。
----------------------------------------------------------------------------------------------------
0100209F E9 76 B2 00 00                 jmp     loc_100D31A
...
0100D31A 83 3C 24 FF                    cmp     [esp+90h+var_90], 0FFFFFFFFh
...
0100D348 E2 FE                          loop    loc_100D348
...
0100D354 FF 73 3C                       push    dword ptr [ebx+3Ch]
...
0100D37C 81 F1 50 45 00+                xor     ecx, 4550h
...
0100D1B2 68 EC 3C 31 66                 push    66313CECh
0100D1B7 E8 8F 02 00 00                 call    Get_API_esi ; CreateSemaphoreA
...
0100D1C6 FF D6                          call    esi
...
0100D1C8 C6 05 9F 20 00+                mov     byte ptr ds:loc_100209F, 0FFh
0100D1CF C7 05 A0 20 00+                mov     dword ptr ds:loc_100209F+1, 101C15h
...
0100D201 C2 2C 00                       retn    2Ch

3、代码加密模式
----------------------------------------------------------------------------------------------------
00401005  E9 12 01 00 00                 jmp     loc_40111C
...
0040111C  68 AA 6A 00 00                 push    6AAAh
...
00401123  E9 02 FF FF FF                 jmp     loc_40102A
...
0040102B  66 81 91 00 32+                adc     word ptr [ecx+403200h], 2FD0h(解密)
...
004010EE  83 E9 02                       sub     ecx, 2
...
00401063  7D C5                          jge     short loc_40102A
...
00401071  E9 6E 8B 00 00                 jmp     near ptr unk_409BE4(病毒体)
...
以下大都相似
...
00409B15  68 FF 60 0A 9A                 push    9A0A60FFh ; CreateSemaphoreA
00409B1A  4F                             dec     edi
00409B1B  E8 33 00 00 00                 call    Get_API_esi
00409B20  89 B5 1F FC FF+                mov     [ebp-3E1h], esi
...
00409868  68 88 DD 02 C5                 push    0C502DD88h
...
00409873  E8 DB 02 00 00                 call    Get_API_esi	; CloseHandle
00409878  FF 74 24 34                    push    dword ptr [esp+34h]
0040987C  FF D6                          call    esi
0040987E
0040987E                 loc_40987E:
0040987E  C6 05 05 10 40+                mov     byte ptr ds:loc_401005, 0FFh
00409885  C7 05 06 10 40+                mov     dword ptr ds:loc_401005+1, 40200415h
0040988F  5F                             pop     edi
00409890  5E                             pop     esi
00409891  5D                             pop     ebp
*/

// 找到最小的本节的CALL(E8)和JUMP(0xe9)
static DWORD Find_Virut_CallJmp(CAntiVirEngine *AVE, BYTE* pBuffer, DWORD Len, DWORD CodePos, DWORD BaseAddress)
{
	int		n;
	DWORD	dwLen = 0;
	DWORD	MaxSectionVA = BaseAddress + Len;
	DWORD	MinCallJmp = 0;
	DWORD	MinCallJmpInSection = 0;
	DWORD	CallJmp;

	dwMisc1(0x70) = 0;
	dwMisc1(0x74) = 0;
	MinCallJmp = MinCallJmpInSection = MaxSectionVA;

	for (int i=0; i<0x800; i++)
	{
		if (CodePos > Len)
		{
			break;
		}
		
		switch (pBuffer[CodePos])
		{
		case 0xe8:
		case 0xe9:
			CallJmp = *(int*)(pBuffer + CodePos + 1) + CodePos + BaseAddress + 5;
			//DebugPrintf("i=%4x, VA= %8x, JmpTo = %x\n", i, CodePos + BaseAddress, Jmp);

			if ( CallJmp > MaxSectionVA && CallJmp < dwHeader1(0x50) && MinCallJmp > CallJmp)
				MinCallJmp = CallJmp;
			else if ( CallJmp < MaxSectionVA && MinCallJmpInSection > CallJmp )
				MinCallJmpInSection = CallJmp;

			//nobreak;

__default:
		default:
			n = AVE->OpLen(pBuffer + CodePos);
			if (n <= 0)
				return RC_DECODE_NULL;

			CodePos += n;
			break;
		}
	}

	dwMisc1(0x70) = MinCallJmpInSection;
	dwMisc1(0x74) = MinCallJmp;

	if (MinCallJmpInSection > MaxSectionVA - 0x1000)
		return RC_DECODE_OK;

	return RC_DECODE_NULL;
}

// 找到本节最后0x1000长度范围内的连续JUMP(0xe9)
static DWORD Find_Virut_JumpCode(CAntiVirEngine *AVE, BYTE* pBuffer, DWORD Len, DWORD CodePos, DWORD BaseAddress, int flag)
{
	int		n,n1;
	DWORD   iNumber = 0x800;
	DWORD	dwLen = 0;
	DWORD	MaxSectionVA = AVE->pPE->section_Entry.VirtualAddress + AVE->pPE->section_Entry.SizeOfRawData;
	DWORD	MaxJmp = 0;
	DWORD	MaxJmpInSection = 0;
	DWORD	Jmp, JmpNext = 0;
	DWORD   JmpLen = 0;
	DWORD   JmpLenMax = 0;
	DWORD   JmpCode;
	int     JmpCodeNum = 0;
	int     JmpNum = 0;
	DWORD   CodePos1 = 0;

	if (flag == 0)                            // 添加判断，以便找到正确的跳转  add by shaojia
	{
		iNumber = 0x1000;
	}
	else if (flag == 1)
	{
		iNumber = 0x8000;
	}
	else if (flag == 2)
	{
		iNumber = 0x80000;
	}

	for (int i=0; i<iNumber; i++)
	{
		if (CodePos > Len || CodePos + BaseAddress > MaxSectionVA || MaxJmpInSection > 0)
		{
			break;
		}


		switch (pBuffer[CodePos])
		{
		case 0xeb:
		case 0xe9:
			if(pBuffer[CodePos] == 0xeb)
			{
				Jmp = *(signed char*)(pBuffer + CodePos + 1) + CodePos + BaseAddress + 2;
				CodePos1 = CodePos + *(signed char*)(pBuffer + CodePos + 1) + 2;
			}
			else
			{
				Jmp = *(int*)(pBuffer + CodePos + 1) + CodePos + BaseAddress + 5;
				CodePos1 = CodePos + *(DWORD*)(pBuffer + CodePos + 1) + 5;
			}
			JmpCodeNum = 0;
			JmpNum = 0;
			for (int j=0; j<40; j++)
			{
				if (CodePos1 > Len || CodePos1 + BaseAddress > MaxSectionVA || MaxJmpInSection > 0)
				{
					break;
				}

				switch(pBuffer[CodePos1])
				{
				case 0xeb:
					JmpNext = *(signed char*)(pBuffer + CodePos1 + 1) + CodePos1 + BaseAddress + 2;
					CodePos1 +=  *(signed char*)(pBuffer + CodePos1 + 1) + 2;
					JmpNum ++;
					JmpCodeNum = 0;
					break;

				case 0xe9:
					JmpNext = *(DWORD*)(pBuffer + CodePos1 + 1) + CodePos1 + BaseAddress + 5;
					CodePos1 +=  *(DWORD*)(pBuffer + CodePos1 + 1) + 5;
					JmpNum ++;
					JmpCodeNum = 0;
					break;

				default:
					n1 = AVE->OpLen(pBuffer + CodePos1);
					if (JmpNum > 0)
					{
						JmpCodeNum += n1;
					}
					if (n1 <= 0)
						return RC_DECODE_NULL;

					if (JmpCodeNum > 0x30)
						break;

					CodePos1 += n1;
					break;
				}
				if (JmpNum >= 3 && JmpNext > MaxSectionVA)
				{
					MaxJmpInSection = Jmp;
					break;
				}
			}

__default:
		default:
			n = AVE->OpLen(pBuffer + CodePos);
			if (n <= 0)
				return RC_DECODE_NULL;

			CodePos += n;
			break;
		}
	}

	//dwMisc1(0x50) = MaxJmpInSection;
	//dwMisc1(0x54) = MaxJmp;

	if (MaxJmpInSection > 0)
		return RC_DECODE_OK;

	return RC_DECODE_NULL;
}

// 找到最大的本节的JUMP(0xe9)
static DWORD Find_Virut_Jump(CAntiVirEngine *AVE, BYTE* pBuffer, DWORD Len, DWORD CodePos, DWORD BaseAddress, int flag)
{
	int		n,n1;
	DWORD   iNumber = 0x800;
	DWORD	dwLen = 0;
	DWORD	MaxSectionVA = AVE->pPE->section_Entry.VirtualAddress + AVE->pPE->section_Entry.SizeOfRawData;
	DWORD	MaxJmp = 0;
	DWORD	MaxJmpInSection = 0;
	DWORD	Jmp;
	DWORD   JmpLen = 0;
	DWORD   JmpLenMax = 0;
	//DWORD   CodePos1 = 0,JmpNext = 0;
	//DWORD   ReSpace = AVE->pPE->section_Entry.SizeOfRawData - AVE->pPE->section_Entry.Misc.VirtualSize;

	if (flag == 0)                            // 添加判断，以便找到正确的跳转  add by shaojia
	{
		iNumber = 0x800;
	}
	else if (flag == 1)
	{
		iNumber = 0x8000;
	}
	else if (flag == 2)
	{
		iNumber = 0x80000;
	}

	dwMisc1(0x50) = 0;
	dwMisc1(0x54) = 0;
	for (int i=0; i<iNumber; i++)
	{
		if (CodePos > Len || CodePos + BaseAddress > MaxSectionVA - 0x200)	// 节表的最后0x200的不在统计范围，因为解密过程也有很多跳转
		{
			break;
		}

		switch (pBuffer[CodePos])
		{
		case 0xe9:
			Jmp = *(int*)(pBuffer + CodePos + 1) + CodePos + BaseAddress + 5;
			//CodePos1 = *(int*)(pBuffer + CodePos + 1) + CodePos + 5;
			//DebugPrintf("i=%4x, VA= %8x, JmpTo = %x\n", i, CodePos + BaseAddress, Jmp);
			JmpLen = *(DWORD*)(pBuffer + CodePos + 1);
			if (JmpLen >= 0xffffff)
			{
				JmpLen = 0- *(DWORD*)(pBuffer + CodePos + 1);
			}

			if ( Jmp > MaxSectionVA && Jmp < dwHeader1(0x50) && MaxJmp < Jmp)
				MaxJmp = Jmp;
			else if ( Jmp < MaxSectionVA && MaxJmpInSection < Jmp && JmpLen > 0x150)
			{
				//JmpLenMax = JmpLen;
				MaxJmpInSection = Jmp;
				//CodePos1 = *(int*)(pBuffer + CodePos + 1) + CodePos + 5;
			}
			//nobreak;

	__default:
		default:
			n = AVE->OpLen(pBuffer + CodePos);
			if (n <= 0)
				return RC_DECODE_NULL;

			CodePos += n;
			break;
		}
	}
	/*
	if (flag == 1 || flag == 2)
	{
		for (int j=0; j<40; j++)
		{
			if (CodePos1 > Len || CodePos1 + BaseAddress > MaxSectionVA)
			{
				break;
			}

			switch(pBuffer[CodePos1])
			{
			case 0xeb:
				JmpNext = *(signed char*)(pBuffer + CodePos1 + 1) + CodePos1 + BaseAddress + 2;
				break;

			case 0xe9:
				JmpNext = *(DWORD*)(pBuffer + CodePos1 + 1) + CodePos1 + BaseAddress + 5;
				break;

			default:
				n1 = AVE->OpLen(pBuffer + CodePos1);
				if (n1 <= 0)
					return RC_DECODE_NULL;

				CodePos1 += n1;
				break;
			}
		}
	}
*/
	dwMisc1(0x50) = MaxJmpInSection;
	dwMisc1(0x54) = MaxJmp;

	if (MaxJmpInSection > MaxSectionVA - 0x1000)
	//if(MaxSectionVA > MaxSectionVA - ReSpace)
		return RC_DECODE_OK;

	return RC_DECODE_NULL;
}

// 遍历指令流，获得病毒下一个入口，加密方法（+、-、^），加密长度，起始地址。
// dwMisc(0/1/2/3) = VirEntry，Method，dwKey，ReadLen，ReadPos
static int Find_Virut_Encrypt(CAntiVirEngine *AVE, BYTE* pBuffer, DWORD Len, DWORD CodePos, DWORD BaseAddress)
{
	int		n;
	DWORD	dwFlag = 0;
	DWORD	dwLen = 0;

	dwMisc1(0x20) = 0;
	dwMisc1(0x24) = 0;
	for (int i=0; i<0x300; i++)
	{
		// 如果越界
		if (CodePos > Len)
		{
			dwMisc1(0x20) = CodePos + BaseAddress;
			dwMisc1(0x24) = MK4CC('V','T','C','D');
			break;
		}

		switch (pBuffer[CodePos])
		{
		case 0x68:
			if (*(DWORD*)(pBuffer + CodePos + 1) < 0x10000)    //添加长度判断，某些是正常程序里用的。   change by shaojia
			{
				dwLen = *(DWORD*)(pBuffer + CodePos + 1);
			}
			CodePos += 5;
			break;

		case 0x58:
		case 0x59:
		case 0x5a:
		case 0x5b:
		case 0x5c:
		case 0x5d:
		case 0x5e:
		case 0x5f:
			if (dwLen != 0 && (dwFlag & 1) == 0)       //添加(dwFlag & 1) == 0 change by shaojia
			{
				dwFlag |= 1;     
				dwMisc1(0x2c) = dwLen;
			}
			CodePos++;
			break;

		case 0xb8:
		case 0xb9:
		case 0xbb:
		case 0xba:		// mov  erx, xxxx	块长度
			if (*(DWORD*)(pBuffer + CodePos + 1) < 0x10000 && (dwFlag & 1) == 0)
			{
				dwFlag |= 1;
				dwMisc1(0x2c) = *(DWORD*)(pBuffer + CodePos + 1);
			}
			CodePos += 5;
			break;

		case 0xf:
			if (pBuffer[CodePos+1] == 0x82)
			{
				dwFlag |= 2;
				CodePos += 6;
			}
			else if (pBuffer[CodePos+1] == 0x83)
			{
				dwFlag |= 2;
				CodePos += 6;
			}
			else if (pBuffer[CodePos+1] == 0x87)                       // 0042A5A6   . /0F87 4F020000             ja      0042A7FB    add by shaojia 2018.01.31
			{
				dwFlag |= 2;
				CodePos += 6;
			}
			else if (pBuffer[CodePos+1] == 0x89)
			{
				dwFlag |= 2;
				CodePos += 6;
			}
			else if (pBuffer[CodePos+1] == 0x8d)
			{
				dwFlag |= 2;
				CodePos += 6;
			}
			else if (pBuffer[CodePos+1] == 0x8f)
			{
				dwFlag |= 2;
				CodePos += 6;
			}
			else
				goto __default;
			break;

		case 0x72:
		case 0x73:
		case 0x79:
		case 0x7d:
		case 0x7F:
			dwFlag |= 2;
			CodePos += 2;
			break;

		case 0xe8:
			CodePos += 5;
			break;

		case 0xe9:
			if (dwFlag == 7 && CodePos + *(DWORD*)(pBuffer + CodePos + 1) > Len)
			{
				dwMisc1(0x20) = *(DWORD*)(pBuffer + CodePos + 1) + 5 + BaseAddress + CodePos;
				if (dwMisc1(0x20) >= dwMisc1(0x30) && dwMisc1(0x30) != 0 && dwMisc1(0x28) != 0)    //change by shaojia
					return RC_DECODE_OK;
			}
			// 拒绝干扰，只有跳到本节的最后200字节内才算跳转：BAD！有病毒向前跳
			//405110 E8 8F 04 00 00                 call    ___security_init_cookie
			//405115 E9 35 FD FF FF                 jmp     ___tmainCRTStartup 
			if (CodePos < 5)
				break;
			if (pBuffer[CodePos - 5] == 0xe8 && *(DWORD*)(pBuffer + CodePos - 4) <= 0xffff && pBuffer[CodePos+4] == 0xff)		// VC7+跳过开始
				CodePos += 5;
			//if (CodePos + *(int*)(pBuffer + CodePos + 1) + 0x1000 < Len)       //注释掉，造成jmp跳转失败。 change by shaojia
				//CodePos += 5;
			else
				CodePos += *(DWORD*)(pBuffer + CodePos + 1) + 5;
			//CodePos += *(DWORD*)(pBuffer + CodePos + 1) + 5;           //int改为DWORD   change by shaojia 2018.01.26
			break;

		case 0xeb:
			// 防止向前跳死循环
			//if (CodePos + *(signed char*)(pBuffer + CodePos + 1) + 0x1000 < Len)               //jmp解密过程向前跳转很正常    change by shaojia 2018.01.25
			//	CodePos += 2;
			//else
			CodePos += *(signed char*)(pBuffer + CodePos + 1) + 2;
			break;

		case 0x66:
			// 66 81 80 FE 59+                add     word ptr [eax+10059FEh], 2F8Bh
			// 66 81 A8 FE FD+                sub     word ptr [eax+100FDFEh], 0D59Ch
			// 66 81 91 00 90+                adc     word ptr [ecx+439000h], 0EA7Ah
			if ((*(WORD*)(pBuffer + CodePos + 1) & 0xc0ff) == 0x8081 && (dwFlag&1) == 1)
			{
				dwFlag |= 4;
				dwMisc1(0x24) = ((pBuffer[CodePos + 2] >> 3) & 7) | 0x40;	// Method 字为单位
				dwMisc1(0x28) = *(WORD*)(pBuffer + CodePos + 7);			// wKey
				dwMisc1(0x30) = *(DWORD*)(pBuffer + CodePos + 3) - dwHeader1(0x34);
				CodePos += 9;
			}
			else
				goto __default;
			break;

		case 0x80:
		case 0x81:
		case 0xC1:
			// 解码方法1
			// 81 AA 00 44 00+                sub     dword ptr [edx+1004400h], 0D87ECB3Bh
			// 80 AA 00 70 40+                sub     byte ptr [edx+407000h], 69h
			if ((*(WORD*)(pBuffer + CodePos) & 0xc0ff) == 0x8081 && dwFlag == 1)
			{
				dwFlag |= 4;
				dwMisc1(0x24) = ((pBuffer[CodePos + 1] >> 3) & 7);	// Method
				dwMisc1(0x28) = *(DWORD*)(pBuffer + CodePos + 6);	// dwKey
				dwMisc1(0x30) = *(DWORD*)(pBuffer + CodePos + 2) - dwHeader1(0x34);
			}
			// 解码方法2
			// 80 92 00 00 41+                adc     ds:Encrypt_Code[edx], 53h
			else if ((*(WORD*)(pBuffer + CodePos) & 0xc0ff) == 0x8080 && dwFlag == 1)
			{
				dwFlag |= 4;
				dwMisc1(0x24) = ((pBuffer[CodePos + 1] >> 3) & 7) | 0x80;	// Method + 字节标志
				dwMisc1(0x28) = *(pBuffer + CodePos + 6);			// Key
				dwMisc1(0x30) = *(DWORD*)(pBuffer + CodePos + 2) - dwHeader1(0x34);
			}
			// C1 81 00 4C 01+                rol     ds:dword_1014C00[ecx], 4
			else if ((*(WORD*)(pBuffer + CodePos) & 0xc0ff) == 0x80C1 && dwFlag == 1)
			{
				dwFlag |= 4;
				dwMisc1(0x24) = ((pBuffer[CodePos + 1] >> 3) & 7) | 8;	// Method
				dwMisc1(0x28) = *(pBuffer + CodePos + 6);	// dwKey
				dwMisc1(0x30) = *(DWORD*)(pBuffer + CodePos + 2) - dwHeader1(0x34);
			}
			// no-break!

__default:
		default:
			if (CodePos>Len-0x10)
				return RC_DECODE_NULL;

			n = AVE->OpLen(pBuffer + CodePos);
			if (n <= 0)
				return RC_DECODE_NULL;

			CodePos += n;
			break;
		}
	}

	return RC_DECODE_NULL;
}

// 遍历指令流，获得原始文件入口地址，目前病毒采取的方法：
// 1、直接对堆栈操作XOR/ADD操作，修改返回地址
// 2、压入立即数，弹出到返回地址

#define BIT_PUSHA		0x00000001
#define BIT_CALL		0x00000002
#define BIT_PUSH_IMM	0x00000004
#define BIT_XOR_EBP		0x00000008
#define BIT_MOV_EBP     0x00000010
#define BIT_XOR_EAX		0x00000020
#define BIT_MOV_EAX		0x00000040

static int Find_Virut(CAntiVirEngine *AVE, BYTE* pBuffer, DWORD Len, DWORD CodePos, DWORD BaseAddress)
{
	int		n;
	DWORD	dwFlag = 0;
	DWORD	_EBP = 0;
	DWORD	OEP = 0;

	dwMisc1(0) = 0;
	dwMisc1(4) = 0;
	for (int i=0; i<0x100; i++)
	{
		// 如果越界
		if (CodePos > Len)
			break;

		switch (pBuffer[CodePos])
		{
		case 1:
			// 87 69 FE       xchg    ebp, [ecx-2]
			// 01 69 FE       add     [ecx-2], ebp
			// 01 6B F8       add     [ebx-8], ebp
			if ((*(WORD*)(pBuffer + CodePos + 1) & 0xf0f8)== 0xf068 && _EBP != 0)
			{
				if (dwMisc1(0) + _EBP >= 0x200 && dwMisc1(0) + _EBP < dwHeader1(0x50))
				{
					dwMisc1(0) += _EBP;
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			// 01 6C 24 24 add    [esp+24h], ebp   //add by shaojia
			else if (*(WORD*)(pBuffer + CodePos + 1) == 0x246c && _EBP != 0)
			{
				if (dwMisc1(0) + _EBP >= 0x200 && dwMisc1(0) + _EBP < dwHeader1(0x50))
				{
					dwMisc1(0) += _EBP;
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			//00409BFD    872B            xchg    dword ptr [ebx], ebp
			//00409BFF    012B            add     dword ptr [ebx], ebp          add by shaojia 2018.01.23
			else if (*(WORD*)(pBuffer + CodePos) == 0x2b01 && _EBP != 0)
			{
				OEP = dwMisc1(0) + _EBP;                                        // 某些样本调用dwMisc1(0) + _EBP存在问题，无法识别  change by shaojia   2018.01.25
				if (OEP >= 0x200 && OEP < dwHeader1(0x50))
				{
					dwMisc1(0) = OEP;
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			goto __default;
			break;

		case 5:
			// 05 11 33 40 00                 add     eax, offset loc_403311
			if ((dwFlag&11) == 22)
			{
				dwMisc1(0) = *(DWORD*)(pBuffer + CodePos + 1) - dwHeader1(0x34);
				dwFlag |= BIT_MOV_EAX;
			}
			CodePos += 5;
			break;

		case 0xf:
			switch ( pBuffer[ CodePos + 1] )
			{
			case 0xc1:
				// 0F C1 69 FE                    xadd    [ecx-2], ebp
				if (*(WORD*)(pBuffer + CodePos + 2) == 0xfe69 && _EBP != 0)
				{
					if (dwMisc1(0) + _EBP >= 0x200 && dwMisc1(0) + _EBP < dwHeader1(0x50))
					{
						dwMisc1(0) += _EBP;
						dwMisc1(4) = MK4CC('V','i','r','u');
						dwMisc1(8) = MK4CC('t', 0, 0, 0);
						return RC_DECODE_OK;
					}
				}
				// 0F C1 6C 24 20 xadd    [esp+20h], ebp
				else if (*(WORD*)(pBuffer + CodePos + 2) == 0x246c && _EBP != 0)
				{
					if (dwMisc1(0) + _EBP >= 0x200 && dwMisc1(0) + _EBP < dwHeader1(0x50))
					{
						dwMisc1(0) += _EBP;
						dwMisc1(4) = MK4CC('V','i','r','u');
						dwMisc1(8) = MK4CC('t', 0, 0, 0);
						return RC_DECODE_OK;
					}
				}
				// OF C1 2B xadd    [ebx], ebp      add by shaojia
				else if (*(WORD*)(pBuffer + CodePos + 1) == 0x2bc1 && _EBP != 0)
				{
					if (dwMisc1(0) + _EBP >= 0x200 && dwMisc1(0) + _EBP < dwHeader1(0x50))
					{
						dwMisc1(0) += _EBP;
						dwMisc1(4) = MK4CC('V','i','r','u');
						dwMisc1(8) = MK4CC('t', 0, 0, 0);
						return RC_DECODE_OK;
					}
				}
				break;
			case 0x84://
				if (_EBP != 0)
				{
					CodePos += *(DWORD*)(pBuffer + CodePos + 2) + 6;
				}
				break;	
			}
			goto __default;
			break;

		case 0x2B:	// sub ebp, ebp
		case 0x33:	// xor ebp, ebp
			if (pBuffer[CodePos+1] == 0xed)
			{
				dwFlag |= BIT_XOR_EBP;
			}
			else if (pBuffer[CodePos+1] == 0xc0)
			{
				dwFlag |= BIT_XOR_EAX;
			}
			goto __default;
			break;

		case 0x83:
			// 83 E5 00                       and     ebp, 0
			if (pBuffer[CodePos+1] == 0xe5 && pBuffer[CodePos+2] == 0)
			{
				dwFlag |= BIT_XOR_EBP;
			}
			//004D1BF5    81F5 70A3FFFF   xor     ebp, FFFFA370
			//004D1BFB    F6D2            not     dl
			//004D1BFD    8D6424 CB       lea     esp, dword ptr [esp-35]
			//004D1C01    FF73 07         push    dword ptr [ebx+7]
			//004D1C04    876B 07         xchg    dword ptr [ebx+7], ebp
			//004D1C07    83E3 00         and     ebx, 0
			//004D1C0A    C2 1C00         retn    1C

			//004D1880    016C24 20       add     dword ptr [esp+20], ebp
			//004D1884    035C24 FC       add     ebx, dword ptr [esp-4]
			                                                                 //add by shaojia 2018.01.24
			else if(pBuffer[CodePos+1] == 0xe3 && pBuffer[CodePos+2] == 0)
			{
				CodePos=dwMisc1(0)-BaseAddress;
				break;
			}
			goto __default;
			break;

		case 0x60:		// PUSHA
			if ((dwFlag & 1) == 0)
			{
				dwFlag |= 1;
				CodePos++;
			}
			else
				return RC_DECODE_NULL;
			break;

		case 0x68:
			if (dwFlag == 3 && *(DWORD*)(pBuffer + CodePos + 1) > dwHeader1(0x34))
			{
				dwMisc1(0) = *(DWORD*)(pBuffer + CodePos + 1) - dwHeader1(0x34);
				dwFlag |= BIT_PUSH_IMM;
			}
			CodePos += 5;
			break;

		case 0x87:
			// 87 6B 1C                       xchg    ebp, [ebx+1Ch]
			if (pBuffer[CodePos + 1] == 0x6b && pBuffer[CodePos + 2] == 0x1c)
			{
				OEP = dwMisc1(0) + _EBP;                                        // 某些样本调用dwMisc1(0) + _EBP存在问题，无法识别  change by shaojia   2018.01.25
				if (OEP >= 0x200 && OEP < dwHeader1(0x50))
				{
					dwMisc1(0) = OEP;
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			// 87 6C 24 3C                    xchg    ebp, [esp+3Ch]
			// 最新的模式，颠倒了2个操作数。mov ebp获得的是差值，而不是一个RVA。在case 0xbd中加了处理。
			if (pBuffer[CodePos + 1] == 0x6c && pBuffer[CodePos + 2] == 0x24)
			{
				OEP = dwMisc1(0) + _EBP;                                        // 某些样本调用dwMisc1(0) + _EBP存在问题，无法识别  change by shaojia   2018.01.25
				if (OEP >= 0x200 && OEP < dwHeader1(0x50))
				{
					dwMisc1(0) = OEP;
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			// 87 43 10                       xchg    eax, [ebx+10h]
			else if (pBuffer[CodePos + 1] == 0x43 && pBuffer[CodePos + 2] == 0x10)
			{
				/*
				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}*/
				OEP = dwMisc1(0) + _EBP;                                        // 某些样本调用dwMisc1(0) + _EBP存在问题，无法识别  change by shaojia   2018.01.25
				if (OEP >= 0x200 && OEP < dwHeader1(0x50))
				{
					dwMisc1(0) = OEP;
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			/*
			//004D1C01    FF73 07         push    dword ptr [ebx+7]
			//004D1C04    876B 07         xchg    dword ptr [ebx+7], ebp
			//            87 6b 07        xchg    [ebx+7], ebp                    add by shaojia 2017.01.24        
			else if (pBuffer[CodePos + 1] == 0x07 && pBuffer[CodePos + 2] == 0x6b)
			{
				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}*/
			goto __default;
			break;

		case 0xbd:
			// BD 22 10 40 00                 mov     ebp, offset loc_401022
			if (*(DWORD*)(pBuffer + CodePos + 1) > dwHeader1(0x34))
			{
				if (*(DWORD*)(pBuffer + CodePos + 1) > 0x80000000)
					_EBP = *(DWORD*)(pBuffer + CodePos + 1);
				else
					dwMisc1(0) = *(DWORD*)(pBuffer + CodePos + 1) - dwHeader1(0x34);

				//if (*(DWORD*)(pBuffer + CodePos + 1) > 0x80000000)
				//	dwMisc1(0) += *(DWORD*)(pBuffer + CodePos + 1);
				//else
				//	dwMisc1(0) = *(DWORD*)(pBuffer + CodePos + 1) - dwHeader1(0x34);  //暂时注释掉，调试某些样本有问题     change by shaojia 2018.01.26
				dwFlag |= BIT_MOV_EBP;
				CodePos += 5;
			}
			break;

		case 0xe8:		// CALL
			// 原始入口的参照
			if ((dwFlag & 2) == 0)
			{
				dwMisc1(0) = BaseAddress + CodePos + 5;

				CodePos += *(DWORD*)(pBuffer + CodePos + 1) + 5;
				dwFlag |= 2;
			}
			else
				return RC_DECODE_NULL;
			break;

		case 0xe9:
			CodePos += *(DWORD*)(pBuffer + CodePos + 1) + 5;
			break;

		case 0xeb:
			CodePos += *(signed char*)(pBuffer + CodePos + 1) + 2;
			break;

		case 0x81:
			// 解码，还原入口
			// 81 74 24 20 8B+                xor     dword ptr [esp+20h], 1038Bh
			// 81 44 24 20 D4+                add     dword ptr [esp+20h], 0FFFFA5D4h
			// 81 44 24 24 ED+                add     dword ptr [esp+24h], 0FFFF5FEDh
			if (((*(DWORD*)(pBuffer + CodePos) & 0xffffc7ff) == 0x20244481 || 
				(*(DWORD*)(pBuffer + CodePos) & 0xffffc7ff) == 0x24244481 ) && (dwFlag&3) == 3)
			{
				switch (((pBuffer[CodePos+1] >> 3) & 7))
				{
				case 0:	// add
					dwMisc1(0) += *(DWORD*)(pBuffer + CodePos + 4);
					break;
				case 5:	// sub
					dwMisc1(0) -= *(DWORD*)(pBuffer + CodePos + 4);
					break;
				case 6:	// xor
					dwMisc1(0) ^= *(DWORD*)(pBuffer + CodePos + 4);
					break;
				}

				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			else if ((*(WORD*)(pBuffer + CodePos) & 0xc7ff) == 0x4381 && (dwFlag&3) == 3)
			{
				switch (((pBuffer[CodePos+1] >> 3) & 7))
				{
				case 0:	// add
					dwMisc1(0) += *(DWORD*)(pBuffer + CodePos + 3);
					break;
				case 5:	// sub
					dwMisc1(0) -= *(DWORD*)(pBuffer + CodePos + 3);
					break;
				case 6:	// xor
					dwMisc1(0) ^= *(DWORD*)(pBuffer + CodePos + 3);
					break;
				}

				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			// 81 C5 CA D4 42+                add     ebp, offset sub_42D4CA
			else if (*(WORD*)(pBuffer + CodePos) == 0xC581)
			{
				if ((dwFlag&0xb) == 0xb)
			{
				_EBP = *(DWORD*)(pBuffer + CodePos + 2);
				dwMisc1(0) = *(DWORD*)(pBuffer + CodePos + 2) - dwHeader1(0x34);
				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
				else if ((dwFlag&0xb) == 3)
				{
					dwMisc1(0) += *(DWORD*)(pBuffer + CodePos + 2);
					if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
					{
						dwMisc1(4) = MK4CC('V','i','r','u');
						dwMisc1(8) = MK4CC('t', 0, 0, 0);
						return RC_DECODE_OK;
					}
				}
			}
			// 81 ED B0 50 BF+                sub     ebp, 0FFBF50B0h
			else if (*(WORD*)(pBuffer + CodePos) == 0xED81 && (dwFlag&0xb) == 0xb)
			{
				_EBP = *(DWORD*)(pBuffer + CodePos + 2);
				dwMisc1(0) = 0 - *(DWORD*)(pBuffer + CodePos + 2) - dwHeader1(0x34);
				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}			}
			// 81 F5 00 A2 FF+                xor     ebp, 0FFFFA200h 可能是加，也可能是减！！！！！！！！！！！！！！
			else if (*(WORD*)(pBuffer + CodePos) == 0xF581 && (dwFlag&0xb) == 0xb)
			{
				_EBP = *(DWORD*)(pBuffer + CodePos + 2);
				OEP = 0 - *(DWORD*)(pBuffer + CodePos + 2) - dwHeader1(0x34);
				if (OEP  >= 0x200 && OEP < dwHeader1(0x50))
				{
					dwMisc1(0) = OEP;
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			// 81 CD D7 AE FF+                or      ebp, 0FFFFAED7h
			else if (*(WORD*)(pBuffer + CodePos) == 0xCD81 && (dwFlag&0xb) == 0xb)
			{
				_EBP = *(DWORD*)(pBuffer + CodePos + 2);
				//OEP = 0 - *(DWORD*)(pBuffer + CodePos + 2) - dwHeader1(0x34);
				OEP = dwMisc1(0) + _EBP;                                                  //change by shaojia    2018.01.31
				if (OEP  >= 0x200 && OEP < dwHeader1(0x50))
				{
					dwMisc1(0) = OEP;
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			goto __default;
			break;

		case 0x8f:
			// 8F 44 24 20                    pop     dword ptr [esp+20h]
			if (*(DWORD*)(pBuffer + CodePos) == 0x2024448F && (dwFlag&7) == 7)
			{
				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			// 8F 43 20                       pop     dword ptr [ebx+20h]
			else if ((*(DWORD*)(pBuffer + CodePos) & 0x00FFC0FF) == 0x20408F && (dwFlag&7) == 7)
			{
				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			goto __default;
			break;

		case 0xc7:
			// C7 44 24 20 A0+                mov     dword ptr [esp+20h], offset sub_4012A0
			if (*(DWORD*)(pBuffer + CodePos) == 0x202444C7 && (dwFlag&3) == 3)
			{
				dwMisc1(0) = *(DWORD*)(pBuffer + CodePos + 4) - dwHeader1(0x34);
				if (/*dwMisc1(0)  >= 0x200 &&*/ dwMisc1(0) < dwHeader1(0x50)) //某样本加了FSG壳，存在dwMisc1(0)小于200的样本，故注释掉dwMisc1(0)  >= 0x200  change by shaojia 2018.01.23
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			// 460039 C7 43 14 80 60+                mov     dword ptr [ebx+14h], offset loc_436080
			else if (*(WORD*)(pBuffer + CodePos) == 0x43C7 && (dwFlag&3) == 3)
			{
				dwMisc1(0) = *(DWORD*)(pBuffer + CodePos + 3) - dwHeader1(0x34);
				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}
			}
			goto __default;
			break;

		case 0xff:
			// FF 64 24 30    jmp     dword ptr [esp+30h] 相当于ret，但堆栈保留了
			// FF 64 24 20    jmp     dword ptr [esp+20h]
			if ((*(DWORD*)(pBuffer + CodePos) == 0x302464ff || *(DWORD*)(pBuffer + CodePos) == 0x202464ff ) && (dwFlag&3) == 3)
			{
				CodePos=dwMisc1(0)-BaseAddress;    //change by shaojia
				break;
				/*
				if (dwMisc1(0)  >= 0x200 && dwMisc1(0) < dwHeader1(0x50))
				{
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}*/
			}
			else if ((pBuffer[CodePos+1] & 0xf8) == 0xf8) 
			{
				// 排除ffff
				return RC_DECODE_NULL;
			}
			// FF 64 24 24    jmp     dword ptr [esp+24h]    add by shaojia
			else if ((*(DWORD*)(pBuffer + CodePos) == 0x242464ff) && (dwFlag&3) == 3)
			{
				CodePos=dwMisc1(0)-BaseAddress;
				break;
				//dwMisc1(0) = BaseAddress + CodePos + 5;
				/*
				if (dwMisc1(0) + _EBP >= 0x200 && dwMisc1(0) + _EBP < dwHeader1(0x50))
				{
					dwMisc1(0) += _EBP;
					dwMisc1(4) = MK4CC('V','i','r','u');
					dwMisc1(8) = MK4CC('t', 0, 0, 0);
					return RC_DECODE_OK;
				}*/
			}
			// FF 64 24 28    jmp     dword ptr [esp+28h]    add by shaojia
			else if ((*(DWORD*)(pBuffer + CodePos) == 0x282464ff) && (dwFlag&3) == 3)
			{
				CodePos=dwMisc1(0)-BaseAddress;
				break;
			}
			goto __default;
			break;

		// 非法、特权、无用指令剔除
		case 0x6c:	// insb
		case 0x6d:	// inswd
		case 0x6e:	// outsb
		case 0x6f:	// outswd
		//case 0x9c:	// pushf
		//case 0x9d:	// popf
		//case 0x9e:	// sahf 
		//case 0x9f:	// lahf
		case 0xca:	// retf
		case 0xc2:	// retf xxxx
		case 0xc3:	// ret
		case 0xcb:	// retf
		case 0xcc:	// int3
		case 0xe4:	// in al,xxx
		case 0xe5:	// im ax,xxx
		case 0xe6:	// out al, xxx
		case 0xe7:	// out al, xxx
		case 0xf4:	// hlt
			return RC_DECODE_NULL;
			break;

__default:
		default:
			if (CodePos>= Len-0x10)			// 越界
				return RC_DECODE_NULL;

			n = AVE->OpLen(pBuffer + CodePos);
			if (n <= 0)
				return RC_DECODE_NULL;

			CodePos += n;
			break;
		}
	}

	return RC_DECODE_NULL;
}

#if DEBUG_CODE
int __thiscall CAntiVirEngine::detect()
#else
int __thiscall CAntiVirEngine::VIRUT_BT_0()
#endif
{	
	AutoPtr pBuffer(this);
	IMAGE_SECTION_HEADER_X *psd;
//	BYTE	*pBuffer = NULL;
	DWORD	ReadPos, ReadLen;	// 相对文件的读取位置和长度
	DWORD	Entry = EP;
	int		i, iRet, iJumpRtn, iFindJmp;
	
	if (File_Length < 0x4c00)
		return RC_DECODE_NULL;

	//DebugPrintf("Check_Sum(B_Entry, 0x40) = %x\n", Check_Sum(B_Entry, 0x40));
	if(Check_Sum(B_Entry, 0x40) == 0xea214ad1)
		return RC_DECODE_NULL;

	// 跳过腾讯vmp误报，Asprotect壳
	if (dwEntry(0) == 0x0003e860 && dwEntry(9) == 0xc355455d)
		return RC_DECODE_NULL;
	// 跳过PE-Armor V0.7X，节名CGG壳
	if (dwEntry(0) == 0x0000e860 && dwEntry(0x14) == 0x41c58156)
		return RC_DECODE_NULL;
    //跳过secureRom壳
	if(Check_Sum(B_Entry, 0x40) == 0x5e1b2933)
		return RC_DECODE_NULL;

	if (wHeader(6) <= 0 || wHeader(6) > 0x16)
		return RC_DECODE_NULL;

	//倒数第一个节是可能是空节，用来迷惑杀毒软件，多次杀毒后会导致有多个空节
	//所以需要找到真正的最后节
	int j = 0;
	psd = (IMAGE_SECTION_HEADER_X *)(B_Header + 0x18 + wHeader(0x14) + (wHeader(6) - 1) * 0x28);
	for (i = wHeader(6) - 1; i >= 0; i--, psd--)
	{
		if (psd->Name[7] == 0 &&
			//psd->SizeOfRawData == 0 &&
			psd->Name[0] >= 'a' && psd->Name[0] <= 'z' &&
			psd->Name[1] >= 'a' && psd->Name[1] <= 'z' &&
			psd->Name[2] >= 'a' && psd->Name[2] <= 'z' &&
			psd->Name[3] >= 'a' && psd->Name[3] <= 'z' &&
			psd->Name[4] >= 'a' && psd->Name[4] <= 'z' &&
			psd->Name[5] >= 'a' && psd->Name[5] <= 'z' &&
			psd->Name[6] >= 'a' && psd->Name[6] <= 'z' )
		{
			if (psd->SizeOfRawData != 0)
			{
				j++;
			}
			continue;
		}
		else
		{
			break;
		}
	}

	_mem_set(B_Misc, 0, 0x80);
	dwMisc(0x34) = wHeader(6) - i - j - 1;	// 节表增加的个数

	if (j != 0)
	{
		for (int z=0; z<j; z++)
		{
			psd++;
		}
	}

	if (psd->SizeOfRawData < 0x4200 && (psd-1)->SizeOfRawData < 0x4200)                    //添加判断，病毒尾节数据小于0x4200，不存在注入代码     add by shaojia   2018.02.04
		return RC_DECODE_NULL;

	dwMisc(0x40) = 0xffffffff;			// 是否存在 stolen code

	// 1.直接查病毒主题是否存在。
	if (EP == EP_Next)
	{
		if (Find_Virut(this, B_Misc, 0x4000, 0x2000, IP32_Entry - 0x2000) == RC_DECODE_OK)
		{
			Find_Virut_CallJmp(this, B_Misc, 0x4000, 0x2000, IP32_Entry - 0x2000);  //add by shaojia
			return RC_DECODE_OK;
		}
	}
	else
	{
		if (Find_Virut(this, B_Misc, 0x4000, 0x2000, IP32_Next - 0x2000) == RC_DECODE_OK)
		{
			Find_Virut_CallJmp(this, B_Misc, 0x4000, 0x2000, IP32_Next - 0x2000);  //add by shaojia
			return RC_DECODE_OK;
		}
	}

	// EP在最后一个节没有加密头
	if (EP > psd->PointerToRawData)
	{
		// 计算读取的起始位置和长度
		ReadLen = EP - psd->PointerToRawData;
		if (ReadLen > 0x10000)
			ReadLen = 0x10000;
		
		ReadPos = EP - ReadLen;
		ReadLen += 0x10000;
		if (ReadLen + ReadPos > File_Length)
			ReadLen = File_Length - ReadPos;
		
		// 增加判断，防止读文件越界,并开辟0x200的内存，防止循环中越界 fixed by wangwei. 2009.7.3
		if (ReadLen > File_Length)
			return RC_DECODE_NULL;

		if (pBuffer.ReadFileToBuffer(ReadPos, ReadLen)!= ReadLen)
			return RC_DECODE_NULL;
		//pBuffer = (BYTE*)New(ReadLen+0x200);
		//if (pBuffer == NULL)
		//	return RC_DECODE_NULL;

		//Seek_Read_Large(ReadPos, pBuffer, ReadLen);
	}
	else 
	{
		// 入口不在最后一个节，可能有加密头
		DWORD dwLen;
		DWORD dwLenJmp;
		/*
		if (EP != EP_Next)
		{
			// 可能存在的加密头，在本节内寻找，出界退出。
			dwLen = pPE->section_Entry.PointerToRawData + pPE->section_Entry.SizeOfRawData - EP_Next;
		}
		else
		{
			// 可能存在的加密头，在本节内寻找，出界退出。
			dwLen = pPE->section_Entry.PointerToRawData + pPE->section_Entry.SizeOfRawData - EP;
		}*/
		dwLen = pPE->section_Entry.PointerToRawData + pPE->section_Entry.SizeOfRawData - EP;
		dwLenJmp = dwLen;     //add by shaojia   2018.01.30
		if (dwLen > 0x2000)
			dwLen = 0x2000;
		/*
		if (EP == EP_Next)
		{
			iRet = Find_Virut_Encrypt(this, B_Misc, dwLen + 0x2000, 0x2000, IP32_Entry - 0x2000);
		}else
		{
			iRet = Find_Virut_Encrypt(this, B_Misc, dwLen + 0x2000, 0x2000, IP32_Next - 0x2000);
		}
		*/
		iRet = Find_Virut_Encrypt(this, B_Misc, dwLen + 0x2000, 0x2000, IP32_Entry - 0x2000);                      //处理某些样本有问题    change by shaojia   2018.01.27
		if (iRet == RC_DECODE_NULL)
		{
			/*
			if (EP == EP_Next)
			{
				Find_Virut_Jump(this, B_Misc, dwLen + 0x2000, 0x2000, IP32_Entry - 0x2000);
			}else
			{
				Find_Virut_Jump(this, B_Misc, dwLen + 0x2000, 0x2000, IP32_Next - 0x2000);
			}
			*/
			dwMisc(0x58) = 0;
			iJumpRtn = Find_Virut_Jump(this, B_Misc, dwLen + 0x2000, 0x2000, IP32_Entry - 0x2000, 0);
			iFindJmp = RC_DECODE_NULL;
			if (iJumpRtn == RC_DECODE_NULL)
			{
				ReadLen =0x1000;
				ReadPos = pPE->section_Entry.PointerToRawData + pPE->section_Entry.SizeOfRawData - 0x1000;
				if (ReadLen + ReadPos > File_Length)
					ReadLen = File_Length - ReadPos;

				// 增加判断，防止读文件越界,并开辟0x200的内存，防止循环中越界
				if (ReadLen > File_Length)
					return RC_DECODE_NULL;

				//pBuffer = (BYTE*)New(ReadLen+0x200);
				//if (pBuffer == NULL)
				//	return RC_DECODE_NULL;

				//Seek_Read_Large(ReadPos, pBuffer, ReadLen);

				if (pBuffer.ReadFileToBuffer(ReadPos, ReadLen) != ReadLen)
					return RC_DECODE_NULL;

				//添加查找段内解密Jmp,如果未找到，跳过继续查找解密  add by shaojia 2018.02.04
				iFindJmp = Find_Virut_JumpCode(this, pBuffer, ReadLen, 0, pPE->section_Entry.VirtualAddress + pPE->section_Entry.SizeOfRawData - 0x1000, 0); 	
			}
			if ( iJumpRtn == RC_DECODE_NULL && dwLenJmp > 0x2000)                      //add by shaojia 2018.01.30
			{
				// 计算读取的起始位置和长度
				ReadLen =dwLenJmp;
				ReadPos = EP;
				if (ReadLen + ReadPos > File_Length)
					ReadLen = File_Length - ReadPos;

				// 增加判断，防止读文件越界,并开辟0x200的内存，防止循环中越界 fixed by wangwei. 2009.7.3
				if (ReadLen > File_Length)
					return RC_DECODE_NULL;

				//pBuffer = (BYTE*)New(ReadLen+0x200);
				//if (pBuffer == NULL)
				//	return RC_DECODE_NULL;

				//Seek_Read_Large(ReadPos, pBuffer, ReadLen);

				if (pBuffer.ReadFileToBuffer(ReadPos, ReadLen) != ReadLen)
					return RC_DECODE_NULL;

				iJumpRtn = Find_Virut_Jump(this, pBuffer, ReadLen, 0, IP32_Entry, 1);
				if ( iJumpRtn == RC_DECODE_NULL)
				{
					iJumpRtn = Find_Virut_Jump(this, pBuffer, ReadLen, 0, IP32_Entry, 2);
				}
			}
			if (iJumpRtn == RC_DECODE_OK)
			{
				dwMisc(0x20) = dwMisc(0x50);
			}
			if (dwMisc(0x20) == 0)
			//if (iJumpRtn == RC_DECODE_NULL)
				dwMisc(0x20) = dwMisc(0x54);
		}

		if (iRet == RC_DECODE_NULL && dwMisc(0x20) < psd->VirtualAddress)
		{
			// 检查下一个入口的合法性，不在最后一个段表明可能是既有引导，也有加密
			// 将下一个入口前后0x1000字节读入内存，再次寻找加密头
			//ReadLen = 0x1000;
			/*
			ReadLen = (pPE->section_Entry.PointerToRawData + pPE->section_Entry.SizeOfRawData - pPE->RVA2FP(dwMisc(0x20)))*2;   //change by shaojia 2018.01.27
			if (ReadLen > 0x2000)
			{
				ReadLen = 0x2000;
			}*/
			ReadLen = 0x2000;                  //修改为读取下一入口前后0x1000字节读入内存，再次寻找加密头，有些样本超过1000字节  change by shaojia   
			ReadPos = pPE->RVA2FP(dwMisc(0x20)) - ReadLen/2;
			if (Seek_Read(ReadPos, B_Temp, ReadLen) != ReadLen)
				return RC_DECODE_NULL;
			iRet = Find_Virut_Encrypt(this, B_Temp, ReadLen, ReadLen/2, dwMisc(0x20) - ReadLen/2);
			if (iRet == RC_DECODE_NULL && dwMisc(0x54) > psd->VirtualAddress)           //如果不加判断，dwMisc(0x20)会被修改为dwMisc(0x54) change by shaojia 2018.01.25
			{
				//	int a=1;
				dwMisc(0x20) = dwMisc(0x54);
				//DebugPrintf("*_* %s\n", Full_Name);
			}
		}

		if (iRet == RC_DECODE_OK)
		{
			// 如果下一个入口跨节，则退出
			if (dwMisc(0x20) <= pPE->section_Entry.VirtualAddress + pPE->section_Entry.Misc.VirtualSize)
			{
				return RC_DECODE_NULL;
			}

			//读入文件，解码
			// dwMisc(0x20/24/28/2c/30) = VirEntry，Method，dwKey，ReadLen，ReadPos
			ReadLen = dwMisc(0x2c);
			ReadPos = pPE->RVA2FP(dwMisc(0x30));
			Entry = pPE->RVA2FP(dwMisc(0x20));

			// 增加判断，防止读文件越界,并开辟0x200的内存，防止循环中越界 fixed by wangwei. 2009.7.3
			if (ReadLen > File_Length)
				return RC_DECODE_NULL;

			//pBuffer = (BYTE*)New(ReadLen+0x200);
			//if (pBuffer == NULL)
			//	return RC_DECODE_NULL;

			//Seek_Read_Large(ReadPos, pBuffer, (ReadLen+0xff)&0xffffff00);


			//加密的内容可能没有加密整个病毒块，必须多读进来一些才能够顺利解码执行
			if (pBuffer.ReadFileToBuffer(ReadPos, (ReadLen + 0xff) & 0xffffff00) != ((ReadLen + 0xff) & 0xffffff00))
				return RC_DECODE_NULL;

			//解密
			int fCarry=0, sCarry;
			for (i=ReadLen; i>=0; i--)
			{
				switch(B_Misc[0x24])
				{
				// 双字解密处置
				case 0:	// add
					*(DWORD*)(pBuffer + i) += dwMisc(0x28);
					i -= 3;
					break;
				case 5:	// sub
					*(DWORD*)(pBuffer + i) -= dwMisc(0x28);
					i -= 3;
					break;
				case 6:	// xor
					*(DWORD*)(pBuffer + i) ^= dwMisc(0x28);
					i -= 3;
					break;

				case 8: // rol
					*(DWORD*)(pBuffer + i) = ROL_D(*(DWORD*)(pBuffer + i), B_Misc[0x28]);
					i -= 3;
					break;

				case 9: // ror
					*(DWORD*)(pBuffer + i) = ROR_D(*(DWORD*)(pBuffer + i), B_Misc[0x28]);
					i -= 3;
					break;

				// 单字解密处置
				case 0x40:	// add
				case 0x42:	// adc
					*(WORD*)(pBuffer + i) += wMisc(0x28);
					i -= 1;
					break;

				case 0x45:	// sub
				case 0x43:	// sbb
					*(WORD*)(pBuffer + i) -= wMisc(0x28);
					i -= 1;
					break;
				case 0x46:	// xor
					*(WORD*)(pBuffer + i) ^= wMisc(0x28);
					i -= 1;
					break;

				case 0x48: // rol
					*(WORD*)(pBuffer + i) = ROL_W(*(WORD*)(pBuffer + i), B_Misc[0x28]);
					i -= 1;
					break;

				case 0x49: // ror
					*(WORD*)(pBuffer + i) = ROR_W(*(WORD*)(pBuffer + i), B_Misc[0x28]);
					i -= 1;
					break;

				// 单字节解密处理，受进位标志影响
				case 0x82:	// adc byte
					sCarry = fCarry;
					if ( *(pBuffer + i) + B_Misc[0x28] + sCarry >= 0x100)
						fCarry = 1;
					else
						fCarry = 0;
					*(pBuffer + i) += B_Misc[0x28] + sCarry;
					break;
				case 0x83:	// sbb byte
					sCarry = fCarry;
					if (*(pBuffer + i) < B_Misc[0x28] + sCarry)
						fCarry = 1;
					else
						fCarry = 0;
					*(pBuffer + i) -= B_Misc[0x28] + sCarry;
					break;

				case 0x80:	// add byte
					*(pBuffer + i) += B_Misc[0x28];
					break;
				case 0x85:	// sub byte
					*(pBuffer + i) -= B_Misc[0x28];
					break;
				default:
					//DebugPrintf("Virut decrypt: Unknow method %x\n", B_Misc[0x24]);
					break;
				}
			}

			ReadLen = (ReadLen+0xff)&0xffffff00;
		}
		else
		{
			// 检查下一个入口的合法性，如果不在最后一个段，则认为非法
			if (dwMisc(0x20) == 0)
			{
				// 没找到不代表文件没有被感染
				dwMisc(0x20) = File_Length - 0x4000 + psd->VirtualAddress - psd->PointerToRawData;
			}
			else if (dwMisc(0x20) < psd->VirtualAddress)
				return RC_DECODE_NULL;

			Entry = dwMisc(0x20) - psd->VirtualAddress + psd->PointerToRawData;

			// 计算读取的起始位置和长度
			ReadLen = Entry - psd->PointerToRawData;
			if (ReadLen > 0x10000)
				ReadLen = 0x10000;
			
			ReadPos = Entry - ReadLen;
			ReadLen += 0x10000;
			if (ReadLen + ReadPos > File_Length)
				ReadLen = File_Length - ReadPos;

			// 增加判断，防止读文件越界,并开辟0x200的内存，防止循环中越界 fixed by wangwei. 2009.7.3
			if (ReadLen > File_Length)
				return RC_DECODE_NULL;
			
			//pBuffer = (BYTE*)New(ReadLen+0x200);
			//if (pBuffer == NULL)
			//	return RC_DECODE_NULL;

			//Seek_Read_Large(ReadPos, pBuffer, ReadLen);

			if (pBuffer.ReadFileToBuffer(ReadPos, ReadLen) != ReadLen)
				return RC_DECODE_NULL;

		}
	}

	// 尝试用虚拟机找到入口
	//VM_VIRUT(this, pBuffer, ReadLen, ReadPos - psd->PointerToRawData + psd->VirtualAddress, Entry);

	//查找原始文件入口或修改跳转的地址
	DWORD VA_ReadPos = pPE->FP2RVA(ReadPos);
	if (Find_Virut(this, pBuffer, ReadLen, Entry - ReadPos, VA_ReadPos) == RC_DECODE_OK)
	{
		Find_Virut_CallJmp(this, pBuffer, ReadLen, Entry - ReadPos, VA_ReadPos);
		//只要入口不在最后一个节，就去尝试搜索跳转修改的字节。
		if (IP32_Entry < psd->VirtualAddress)
		{
			// 搜索要还原的指令位置
			/*
			01007556  FF 95 AF 41 00+                call    dword ptr [ebp+41AFh]
			0100755C  8D 57 73                       lea     edx, [edi+73h]
			0100755F
			0100755F                 loc_100755F:                            ; CODE XREF: _5035.e
			0100755F  C6 05 12 27 00+                mov     byte ptr ds:loc_1002712, 0FFh
			01007566  8D 98 1C C4 43+                lea     ebx, [eax-3ABC3BE4h]
			0100756C  4E                             dec     esi
			0100756D  C7 05 13 27 00+                mov     dword ptr ds:loc_1002712+1, 105415h
			01007577  8B DC                          mov     ebx, esp
			01007579  FC                             cld
			0100757A  61                             popa
			0100757B  E9 03 01 00 00                 jmp     locret_1007683
			*/

			/*DWORD	dwFlag = 0;

			for (i=0; i<=ReadLen; i++)
			{
				if (*(WORD*)(pBuffer + i) == 0x5c6 && *(DWORD*)(pBuffer + i + 2) == dwMisc(0) + dwHeader(0x34))
				{
					//DebugPrintf("=====> %2x\n", pBuffer[i + 6]); 一定是0xff
					dwFlag |= 1;
					B_Misc[0x44] = pBuffer[i + 6];
					break;
				}
			}

			for ( ; i<ReadLen; i++)
			{
				if (*(WORD*)(pBuffer + i) == 0x5c7 && *(DWORD*)(pBuffer + i + 2) == dwMisc(0) + dwHeader(0x34) + 1)
				{
					dwFlag |= 2;
					dwMisc(0x45) = *(DWORD*)(pBuffer + i + 6);
					break;
				}
			}
			
			//写入的文件偏移
			if (dwFlag == 3)
			{
				dwMisc(0x40) = dwMisc(0) - dwHeader(0x28) + EP;
			}
			*/

			for (i=0; i<=ReadLen; i++)
			{ 
				//if (*(WORD*)(pBuffer + i) == 0x5c7 && *(WORD*)(pBuffer + i + 6) == 0x15ff)
				//00449858    C705 86134000 E815AF00      mov     dword ptr [401386], 0AF15E8
				//00449862    C605 8A134000 00            mov     byte ptr [40138A], 0                 增加15E8，change by shaojia
				if (*(WORD*)(pBuffer + i) == 0x5c7 && (*(WORD*)(pBuffer + i + 6) == 0x15ff || *(WORD*)(pBuffer + i + 6) == 0x15e8))
				{
					for (int j=i+0xa; j<i+0x100; j++)
					{
						if (*(WORD*)(pBuffer + j) == 0x5c6 && *(DWORD*)(pBuffer + j + 2) == *(DWORD*)(pBuffer + i + 2) + 4)
						{
							// found！！！
							dwMisc(0x40) = *(DWORD*)(pBuffer + i + 2) - dwHeader(0x34) - dwHeader(0x28) + EP;
							B_Misc[0x48] = pBuffer[j + 6];
							dwMisc(0x44) = *(DWORD*)(pBuffer + i + 6);
							i=ReadLen;

							// Delete(pBuffer);
							return RC_DECODE_OK;
						}
					}
				}
				else if (*(WORD*)(pBuffer + i) == 0x5c6)
				{
					for (int j=i+6; j<i+0x100; j++)
					{
						if (*(WORD*)(pBuffer + j) == 0x5c7 && *(DWORD*)(pBuffer + j + 2) == *(DWORD*)(pBuffer + i + 2) + 1)
						{
							// found！！！
							dwMisc(0x40) = *(DWORD*)(pBuffer + i + 2) - dwHeader(0x34) - dwHeader(0x28) + EP;
							B_Misc[0x44] = pBuffer[i + 6];
							dwMisc(0x45) = *(DWORD*)(pBuffer + j + 6);
							i=ReadLen;

							// Delete(pBuffer);
							return RC_DECODE_OK;
							break;
						}
					}
				}
			}
		}

		// Delete(pBuffer);
		return RC_DECODE_OK;
	}
	//else
	//{
		// 全缓冲区搜索 2009.2.9
		/*
			修改入口附近指令模式：
			01016D92  C7 05 E5 74 00 01 FF 15 D0 10  mov     dword ptr ds:loc_10074E5, 10D015FFh
			01016D9C  F8                             clc
			01016D9D  C6 05 E9 74 00 01 00           mov     byte ptr ds:loc_10074E5+4, 0
			--------------------------------------------------------------------------------------
			0044401A  C6 05 DE 9A 40+                mov     byte ptr ds:loc_409ADE, 0FFh
			00444021  C7 05 DF 9A 40+                mov     dword ptr ds:loc_409ADE+1, 41107C15h
			--------------------------------------------------------------------------------------
			修改入口模式：
			01009679  8B 5C 24 24                    mov     ebx, [esp+20h+arg_0]
			0100967D  68 09 25 00 01                 push    offset loc_1002509
			01009682  83 F0 28                       xor     eax, 28h
			01009685  80 CE 9E                       or      dh, 9Eh
			01009688  8F 44 24 20                    pop     [esp+24h+var_4]
			0100968C  E9 6C FD FF FF                 jmp     loc_10093FD
			--------------------------------------------------------------------------------------
			00406011  8B 6C 24 20                    mov     ebp, [esp+20h]
			00406015  8B 5C 24 24                    mov     ebx, [esp+20h+arg_0]
			00406019  C7 44 24 20 CF+                mov     dword ptr [esp+20h], offset sub_401ECF
			00406021  E9 B9 02 00 00                 jmp     loc_4062DF
			--------------------------------------------------------------------------------------
			晕，顺序竟然也颠倒
			0001527A  68 00 30 01 00                 push    offset sub_13000
			0001527F  86 E0                          xchg    ah, al
			00015281  21 D2                          and     edx, edx
			00015283  96                             xchg    eax, esi
			00015284  8B 6C 24 24                    mov     ebp, [esp+24h]
			00015288  8F 43 20                       pop     dword ptr [ebx+20h]
			--------------------------------------------------------------------------------------
			00503E22  21 6B 14                       and     [ebx+14h], ebp;=0
			...可能有垃圾指令
			00503E25  81 ED 50 42 B0+                sub     ebp, -4FBDB0h ;Original IP
			00503E2B  B1 CB                          mov     cl, 0CBh...
			00503E2D  01 6B 14                       add     [ebx+14h], ebp
			00503E30  E9 CB B1 FF FF                 jmp     loc_4FF000
			--------------------------------------------------------------------------------------
			10075DF  60                             pusha
			...
			10075E8  81 C5 03 27 00+                add     ebp, offset loc_1002703 <------ Original IP
			...
			10075F3  8D 5C 24 08                    lea     ebx, [esp+24h+var_1C] <---- return pointer
			10075F7  E9 CA FE FF FF                 jmp     loc_10074C6
		*/

		//DebugWriteFile("d:\\kvtest\\1.bin", pBuffer, ReadLen);
		//int a=1;

		// 搜索分割成2部分，首先搜索修改指令的方式，其次搜索入口
		/*
		for (i=0; i<=ReadLen; i++)
		{
			if (*(WORD*)(pBuffer + i) == 0x5c7)
			{
				for (int j=i+0xa; j<i+0x100; j++)
				{
					if (*(WORD*)(pBuffer + j) == 0x5c6 && *(DWORD*)(pBuffer + j + 2) == *(DWORD*)(pBuffer + i + 2) + 4)
					{
						// found！！！
						dwMisc(0x40) = *(DWORD*)(pBuffer + i + 2) - dwHeader(0x34) - dwHeader(0x28) + EP;
						B_Misc[0x48] = pBuffer[j + 6];
						dwMisc(0x44) = *(DWORD*)(pBuffer + i + 6);
						i=ReadLen;

						Delete(pBuffer);
						return RC_DECODE_OK;
					}
				}
			}
			else if (*(WORD*)(pBuffer + i) == 0x5c6)
			{
				for (int j=i+6; j<i+0x100; j++)
				{
					if (*(WORD*)(pBuffer + j) == 0x5c7 && *(DWORD*)(pBuffer + j + 2) == *(DWORD*)(pBuffer + i + 2) + 1)
					{
						if (pBuffer[i + 6] != 0xff && pBuffer[i + 6] != 0xe8)
							break;

						// found！！！
						dwMisc(0x40) = *(DWORD*)(pBuffer + i + 2) - dwHeader(0x34) - dwHeader(0x28) + EP;
						B_Misc[0x44] = pBuffer[i + 6];
						dwMisc(0x45) = *(DWORD*)(pBuffer + j + 6);
						i=ReadLen;

						Delete(pBuffer);
						return RC_DECODE_OK;
					}
				}
			}
		}*/
	/*
		// 搜索入口
		for (i=0; i<=ReadLen; i++)
		{
			if (*(DWORD*)(pBuffer + i) == 0x24245C8B)
			{
				DWORD dw = 0;
				for (int j=i+4; j<i+0x20; j++)
				{
					if (*(DWORD*)(pBuffer + j) == 0x202444C7)
					{
						// found！！！
						dwMisc(0) = *(DWORD*)(pBuffer + i + 4) - dwHeader(0x34);

						Delete(pBuffer);
						return RC_DECODE_OK;
					}
					else if (pBuffer[j] == 0x68)
					{
						dw = *(DWORD*)(pBuffer + j + 1);
					}
					else if (*(DWORD*)(pBuffer + j) == 0x2024448F && dw > dwHeader(0x34))
					{
						dwMisc(0) = dw - dwHeader(0x34);

						Delete(pBuffer);
						return RC_DECODE_OK;
					}
				}
			}
			else if (*(DWORD*)(pBuffer + i) == 0x24246C8B)
			{
				DWORD dw = 0;
				for (int j=i-0x20; j<i+0x20; j++)
				{
					if (pBuffer[j] == 0x68)
					{
						dw = *(DWORD*)(pBuffer + j + 1);
					}
					else if ((*(DWORD*)(pBuffer + j) & 0xffc8ff) == 0x20408F   && dw > dwHeader(0x34))
					{
						dwMisc(0) = dw - dwHeader(0x34);
						dwMisc(4) = MK4CC('V','i','r','u');

						Delete(pBuffer);
						return RC_DECODE_OK;
					}
				}
			}
			else if (*(pBuffer + i) == 0x21 && *(pBuffer + i + 1) == 0x6B && *(pBuffer + i + 2) == 0x14)
			{
				for (int j=i+3; j<i+0x20; j++)
				{
					if ( *(pBuffer + j) == 0x81 && *(pBuffer + j + 1) == 0xed)
					{
						dwMisc(0) = 0 - *(DWORD*)(pBuffer + j + 2) - dwHeader(0x34);
						dwMisc(4) = MK4CC('V','i','r','u');

						Delete(pBuffer);
						return RC_DECODE_OK;
					}
				}
			}
			else if (*(pBuffer + i) == 0x81 && *(pBuffer + i + 1) == 0xc5)
			{
				for (int j=i+6; j<i+0x20; j++)
				{
					if (*(DWORD*)(pBuffer + j) == 0x08245c8d)
					{
						dwMisc(0) = *(DWORD*)(pBuffer + i + 2) - dwHeader(0x34);
						dwMisc(4) = MK4CC('V','i','r','u');

						Delete(pBuffer);
						return RC_DECODE_OK;
					}
				}
			}
		}
	}*/

	// Delete(pBuffer);
	return RC_DECODE_NULL;
}

#if DEBUG_CODE
int __thiscall CAntiVirEngine::clean()
#else
int __thiscall CAntiVirEngine::VIRUT_BT_1()
#endif
{	
	DWORD NewLen;

	dwHeader(6) -= dwMisc(0x34);

	if (dwMisc(0x40) != 0xffffffff)
	{
		Seek_Write(dwMisc(0x40), B_Misc + 0x44, 5);
		dwMisc(0) = dwHeader(0x28);
	}

	// 有解密长度就以此为病毒长度，没有就假设病毒长度为0x4000。
	if (dwMisc(4) == MK4CC('V','i','r','u'))
		NewLen = File_Length - 0x4000;
	else if (dwMisc(0x2c) == 0)
		NewLen = File_Length - 0x2000;
	else
		NewLen = File_Length - dwMisc(0x2c);

	EP = NewLen;
	if (dwMisc(0x30) != 0x00)
	{
		//EP = dwMisc(0x30);
		EP = pPE->RVA2FP(dwMisc(0x30)); //change by shaojia
		EP = (EP+0xff)&0xffffff00;
	}
	if (dwMisc(0x70) != 0x00 && dwMisc(0x30) == 0x00 && EP > pPE->RVA2FP(dwMisc(0x70)))
	{
		EP = pPE->RVA2FP(dwMisc(0x70)); //change by shaojia
		EP = EP&0xffffff00;
	}
	return RC_CLEAN_NEXT;
}