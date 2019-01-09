#include "virut_sig.h"

//                                                     这里没写反.
//                                           闲置      1代    3代    2代    4代    5代    6代    7代    8代
//              virutkind                       0      1      2      3      4      5      6      7      8
WORD recover_off[MAXKIND + 1] =            { 0x0000,0x0173,0x00b4,0x00c2,0x00b5,0x00b4,0x00b5,0x00b4,0x009f };
WORD backvalue_off[MAXKIND + 1] =          { 0x0000,0x0000,0x00fa,0x00fc,0x00fe,0x00fa,0x00f9,0x00fa,0x0008 };

int blockdescript_offset[MAXKIND + 1] =    { 0x0000,0x0000,0x059e,0x05a1,0x05b1,0x05ab,0x05a1,0x0594,0x0548 };
WORD dw_key_sig[MAXKIND + 1] =             { 0x0000,0x0000,0xefb5,0x0035,0xf1b3,0xfb7f,0x03fb,0xefb5,0x0011 };
BYTE db_before_sig[MAXKIND + 1][5] =
{
	{ 0 },
{ 0 },
{ 0xe9,0x10,0x01,0x00,0x00 },
{ 0xe9,0x2d,0x01,0x00,0x00 },
{ 0xe9,0x2d,0x01,0x00,0x00 },
{ 0xe9,0x2d,0x01,0x00,0x00 },
{ 0xe9,0x2d,0x01,0x00,0x00 },     //6
{ 0xe9,0x10,0x01,0x00,0x00 },
{ 0xe9,0xdd,0x00,0x00,0x00 }
};

sig_struct FuckedVirut[MAXKIND + 1] = 
{ 
	//第一种变种标记赋值


	//第二种变种标记赋值
	{
        0xb4,
        0xfa,
        0x59e,
        0x600,
        0xefb5,
        { 0xe9,0x10,0x01,0x00,0x00 },
        4 + 1,
        {
			{0, FALSE, FALSE, 0, NULL, 0, 0, 1, {"83 3c 24 fe"}, {0}},         //cmp dword ptr[esp], -2
			{1, TRUE,  FALSE, 0, NULL, 0, 0, 1, {"68 4a 90 c5 01"}, {1}},      // push xx
			{2, FALSE, FALSE, 0, NULL, 0, 0, 1, {"89 74 24 44"}, {2}},         //mov [esp+44h],esi
            {4, FALSE, TRUE },
			{5, FALSE, FALSE, 0, NULL ,0, 0, 1, {"64 8b 15 30 00 00 00"}, {3}} //mov edx, large fs:30h
        },
        8,
        TRUE,
        "8b ff",    //mov edi,edi
        2,
        encrypt_2,
        decrypt_2,
        updatekey_2
	},
	//第三种变种标记赋值
	{
		0xc2,
		0xfc,
		0x5a1,
		0x600,
		0x35,
		{ 0xe9,0x2d,0x01,0x00,0x00 },
		4 + 1,
		{
			{ 0, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "83 ec 2c" }, {0} },         //sub esp,0x2c
			{ 1, TRUE,  FALSE, 0, NULL, 0, 0, 1,{ "66 81 BB 80 1B 00 00 4D 5A" }, {1} },      // cmp     word ptr [ebx+1B80h], 5A4Dh
			{ 2, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "8F 44 24 44" }, {2} },         //pop     [esp+30h+arg_10]
			{ 4, FALSE, TRUE },
			{ 5, FALSE, FALSE, 0, NULL ,0, 0, 1,{ "68 19 02 8C A5" }, {3} } //push    0A58C0219h
		},
		7,
	    FALSE,
		NULL,
		0,
		NULL,
		NULL,
		NULL
	},
	//第四种变种标记赋值
	{
		0xb5,
		0xfe,
		0x5b1,
		0x600,
		0xf1b3,
		{ 0xe9,0x2d,0x01,0x00,0x00 },
		4 + 1,
		{
			{ 0, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "83 3c 24 ff" }, {0} },         // cmp dword ptr [esp],-1
			{ 1, TRUE,  FALSE, 0, NULL, 0, 0, 1,{ "0f b7 cb" }, {1} },			// movzx ecx,bx
			{ 2, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "89 74 24 44" }, {2} },         // mov [esp+44h],esi
			{ 4, FALSE, TRUE },
			{ 6, FALSE, FALSE, 0, NULL ,0, 0, 1,{ "f7 5c 24 04" }, {3} }			//neg dword ptr [esp + 4]
		},
		7,
		FALSE,
		NULL,
		0,
		NULL,
		NULL,
		NULL
	},
	//第五种变种标记赋值
	{
		0xb4,
		0xfa,
		0x5ab,
		0x600,
		0xfb7f,
        { 0xe9,0x2d,0x01,0x00,0x00 },
        4 + 1,
        {
			{ 0, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "8d 64 24 d0" }, {0} },         // lea esp, [esp-0x30]
			{ 1, TRUE,  FALSE, 0, NULL, 0, 0, 1,{ "0f 91 c0" }, {1} },			// setno al
			{ 3, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "83 7c 24 34 04" }, {2} },         // mov [esp+34h],4
            { 4, FALSE, TRUE },
			{ 6, FALSE, FALSE, 0, NULL ,0, 0, 1,{ "f7 5c 24 04" }, {3} }			//neg dword ptr [esp + 4]
        },
        7,
        TRUE,
        "8d 49 00",  //lea ecx,[ecx+0]
        3,
        NULL,
        NULL,
        NULL
	},

	//第六种变种标记赋值
	{
		0xb5,
		0xf9,
		0x5a1,
		0x600,
		0x3fb,
		{ 0xe9,0x2d,0x01,0x00,0x00 },
		4 + 1,
		{
			{ 0, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "83 ec 30" }, {0} },         // sub esp,0x30
			{ 1, TRUE,  FALSE, 0, NULL, 0, 0, 1,{ "0f b7 93 bc 1c 00 00" }, {1} },			// movzx edx,word ptr [ebx+1cbch]
			{ 3, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "87 44 24 34" }, {2} },         // xchg eax,[esp+34h]
		    { 4, FALSE, TRUE },
			{ 6, FALSE, FALSE, 0, NULL ,0, 0, 1,{ "f7 54 24 04" }, {3} }			//not [esp+4]
		},
        7,
        TRUE,
        "8d 49 00",  //lea ecx,[ecx+0]
        3,
        NULL,
        NULL,
        NULL
	    },
	//第七种变种标记赋值
	{
		0xb4,
		0xfa,
		0x594,
		0x600,
		0xefb5,
		{ 0xe9,0x10,0x01,0x00,0x00 },
		4 + 1,
		{
			{ 0, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "83 3c 24 fe" }, {0} },         //cmp dword ptr[esp], -2
			{ 1, TRUE,  FALSE, 0, NULL, 0, 0, 1,{ "68 A1 A0 55 12" }, {1} },      // push xx
			{ 2, FALSE, FALSE, 0, NULL, 0, 0, 1,{ "89 74 24 44" }, {2} },         //mov [esp+44h],esi
		    { 4, FALSE, TRUE },
			{ 5, FALSE, FALSE, 0, NULL ,0, 0, 1,{ "64 8b 15 30 00 00 00" }, {3} } //mov edx, large fs:30h
		},
		8,
		TRUE,
		"8b ff",    //mov edi,edi
		2,
		encrypt_2,
		decrypt_2,
		updatekey_2
	},
	//第八种变种标记赋值
	{
		0x9f,
		0x8,
		0x548,
		0x600,
		0x11,
		{ 0xe9,0xdd,0x00,0x00,0x00 },
		3,
		{
			{ 1, TRUE,  FALSE, 1, "0f 84", 2, 4, 1,{ "0f a2" }, {0} },         // jz  cpuid
			{ 3, FALSE, FALSE, 1, "0f 84", 2, 4, 1,{ "66 C1 E9 03" }, {1} },   //jz   shr cx,3
			{ 4, FALSE, FALSE, 0, NULL,    0, 0, 2,{"8b ce","68 4c 13 79 60"},{2,3}}, //mov ecx,esi  push 6079134Ch
		},
		7,
		TRUE,
		"8d 49 00",    //lea ecx, [ecx+0]
		3,
		NULL,
		NULL,
		NULL
	},

};

//
void encrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
	;
}
void decrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
	;
}
void updatekey_2(WORD* key, WORD dw_key_sig, WORD times)
{
	;
}






