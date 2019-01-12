#include "virut_sig.h"


sig_struct FuckedVirut[MAXKIND + 1] = 
{
    //第0种, 空着
    {
        0
    },
	//第一种变种标记赋值
	{
		0x173,
		0xe7,
		0x53c,
		0x500,   //0x408
		0xd,
        { 0x8b, 0xee, 0x81, 0xee, 0x00, 0x12, 0x1b, 0x00 },
        0x1f,
        8,
        2,
        {
			{ 1, TRUE,  TRUE,  1, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "8b 6c 24 20","80 3B 4D" },{ 0,1 } },         // jz; mov ebp, [esp+0x20]; cmp byte ptr [ebx], 4Dh 
			{ 4, FALSE, FALSE, 2, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "66 8c c8","66 c1 e8 05" },{ 2,3 } },         // jz; mov ax, cs; shr ax,5
        },
        8,
        TRUE,
        "8d 49 00",    //lea ecx, [ecx+0]
        3,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},

	//第二种变种标记赋值
	{
        0xb4,
        0xfa,
        0x59e,
        0x600,
        0xefb5,
        { 0xe9,0x10,0x01,0x00,0x00 },
        0,
        5,
        4 + 1,
        {
			{0, FALSE, FALSE, 0, { 0 }, { 0 }, { 0 }, 1, {"83 3c 24 fe"}, {0}},         //cmp dword ptr [esp], -2
			{1, TRUE,  FALSE, 0, { 0 }, { 0 }, { 0 }, 2, {"68 4A 90 C5 01","68 C9 BC 94 90"}, {1,1}},      // dec ebx  dec bx
			{2, FALSE, FALSE, 0, { 0 },{ 0 },{ 0 }, 1, {"89 74 24 44"}, {3}},         //mov [esp+44h],esi
            {4, FALSE, TRUE },
			{5, FALSE, FALSE, 0, { 0 },{ 0 },{ 0 }, 1, {"64 8b 15 30 00 00 00"}, {3}} //mov edx, large fs:30h
        },
        8,
        TRUE,
        "8b ff",    //mov edi,edi
        2,
        (pEncryptFuncAddr)encrypt_2,
        (pDecryptFuncAddr)decrypt_2,
        (pUpdateKeyFuncAddr)updatekey_1
	},
	//第三种变种标记赋值
	{
		0xc2,
		0xfc,
		0x5a1,
		0x600,
		0x35,
		{ 0xe9,0x2d,0x01,0x00,0x00 },
        0,
        5,
		4 + 1,
		{
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 ec 2c" }, {0} },         //sub esp,0x2c
			{ 1, TRUE,  FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "66 81 BB 80 1B 00 00 4D 5A" }, {1} },      // cmp     word ptr [ebx+1B80h], 5A4Dh
			{ 2, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "8F 44 24 44" }, {2} },         //pop     [esp+30h+arg_10]
			{ 4, FALSE, TRUE },
			{ 5, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "68 19 02 8C A5" }, {3} } //push    0A58C0219h
		},
		7,
	    FALSE,
		NULL,
		0,
        (pEncryptFuncAddr)encrypt_3,
        (pDecryptFuncAddr)decrypt_3,
        (pUpdateKeyFuncAddr)updatekey_1
	},
	//第四种变种标记赋值
	{
		0xb5,
		0xfe,
		0x5b1,
		0x600,
		0xf1b3,
		{ 0xe9,0x2d,0x01,0x00,0x00 },
        0,
        5,
		4 + 1,
		{
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 3c 24 ff" }, {0} },         // cmp dword ptr [esp],-1
			{ 1, TRUE,  FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "0f b7 cb" }, {1} },			// movzx ecx,bx
			{ 2, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "89 74 24 44" }, {2} },         // mov [esp+44h],esi
			{ 4, FALSE, TRUE },
			{ 6, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "f7 5c 24 04" }, {3} }			//neg dword ptr [esp + 4]
		},
		7,
		FALSE,
		NULL,
		0,
        (pEncryptFuncAddr)encrypt_2,
        (pDecryptFuncAddr)decrypt_2,
        (pUpdateKeyFuncAddr)updatekey_1
	},
	//第五种变种标记赋值
	{
		0xb4,
		0xfa,
		0x5ab,
		0x600,
		0xfb7f,
        { 0xe9,0x2d,0x01,0x00,0x00 },
        0,
        5,
        4 + 1,
        {
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "8d 64 24 d0" }, {0} },         // lea esp, [esp-0x30]
			{ 1, TRUE,  FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "0f 91 c0" }, {1} },			// setno al
			{ 3, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 7c 24 34 04" }, {2} },         // mov [esp+34h],4
            { 4, FALSE, TRUE },
			{ 6, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "f7 5c 24 04" }, {3} }			//neg dword ptr [esp + 4]
        },
        7,
        TRUE,
        "8d 49 00",  //lea ecx,[ecx+0]
        3,
        (pEncryptFuncAddr)encrypt_2,
        (pDecryptFuncAddr)decrypt_2,
        (pUpdateKeyFuncAddr)updatekey_1
	},

	//第六种变种标记赋值
	{
		0xb5,
		0xf9,
		0x5a1,
		0x600,
		0x3fb,
		{ 0xe9,0x2d,0x01,0x00,0x00 },
        0,
        5,
		4 + 1,
		{
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 ec 30" }, {0} },         // sub esp,0x30
			{ 1, TRUE,  FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "0f b7 93 bc 1c 00 00" }, {1} },			// movzx edx,word ptr [ebx+1cbch]
			{ 3, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "87 44 24 34" }, {2} },         // xchg eax,[esp+34h]
		    { 4, FALSE, TRUE },
			{ 6, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "f7 54 24 04" }, {3} }			//not [esp+4]
		},
        7,
        TRUE,
        "8d 49 00",  //lea ecx,[ecx+0]
        3,
        (pEncryptFuncAddr)encrypt_2,
        (pDecryptFuncAddr)decrypt_2,
        (pUpdateKeyFuncAddr)updatekey_1
	    },
	//第七种变种标记赋值
	{
		0xb4,
		0xfa,
		0x594,
		0x600,
		0xefb5,
		{ 0xe9,0x10,0x01,0x00,0x00 },
        0,
        5,
		4 + 1,
		{
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 3c 24 fe" }, {0} },         //cmp dword ptr[esp], -2
			{ 1, TRUE,  FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "68 A1 A0 55 12" }, {1} },      // push xx
			{ 2, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "89 74 24 44" }, {2} },         //mov [esp+44h],esi
		    { 4, FALSE, TRUE },
			{ 5, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "64 8b 15 30 00 00 00" }, {3} } //mov edx, large fs:30h
        },
        8,
        TRUE,
        "8b ff",    //mov edi,edi
        2,
        (pEncryptFuncAddr)encrypt_2,
        (pDecryptFuncAddr)decrypt_2,
        (pUpdateKeyFuncAddr)updatekey_1
    },
    //第八种变种标记赋值
    {
        0x9f,
        0x8,
        0x548,
        0x600,
        0x11,
        { 0xe9,0xdd,0x00,0x00,0x00 },
        0,
        5,
        3,
        {
            { 1, TRUE,  FALSE, 1, {"0f 84","74"}, {2,1}, {4,1}, 4,{ "0f a2","bd","0F C1 6C 24 20","C1 FB 18" }, {0,1,2,3} },         // jz  cpu
            { 3, FALSE, FALSE, 1, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "66 C1 E9 03","64 ff 36" }, {4,5} },   
            { 4, FALSE, FALSE, 0, { 0 },{ 0 },{ 0 }, 1,{"8b ce"},{6}}, //mov ecx,esi
        },
        7,
        TRUE,
        "8d 49 00",    //lea ecx, [ecx+0]
        3,
        (pEncryptFuncAddr)encrypt_4,
        (pDecryptFuncAddr)decrypt_4,
        (pUpdateKeyFuncAddr)updatekey_2
    },
            //第九种
    {
        0xc7,
        0x10a,
        0x5a1,
        0x600,
        0x3d,
        {0xe9, 0x2d, 0x01, 0x00, 0x00},
        0,
        5,
        4 + 1,
        {
            { 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 ec 2c" }, {0} },  //sub esp, 2ch
            { 1, TRUE,  FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "03 8B 80 1C 00 00" }, {1} },  //add     ecx, [ebx+1C80h]
            { 2, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "8F 44 24 44" }, {2} },  //pop     dword ptr [esp+44h]
            { 4, FALSE, TRUE },
            { 5, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "68 A5 A3 9C 2E" }, {3} }  //push    2E9CA3A5h
        },
        7,
        TRUE,
        "8b ff",
        2,
        (pEncryptFuncAddr)encrypt_5,
        (pDecryptFuncAddr)decrypt_5,
        (pUpdateKeyFuncAddr)updatekey_1
    },
            //第a种
    {
        0xa8,
        0xb6,
        0x55e,
        0x800,   //79c
        0x17,
        {0xe9, 0xf3, 0x0, 0x0, 0x0},
        0,
        5,

        3 + 1,
        {
            {0,FALSE,FALSE, 0, {0}, {0}, {0}, 1, {"83 c4 e0"}, {0}},
            {1,TRUE,FALSE, 1, {"0f 84","74"},{2,1},{4,1}, 2, {"0F C1 6C 24 28","66 81 E3 00 88"}, {1,2}},
            {4, FALSE, TRUE},
            {6, FALSE,FALSE,0,{ 0 },{ 0 },{ 0 }, 2, {"6a 01","6a ff"},{3,4}}
        },
        7,
        FALSE,
        NULL,
        0,
        (pEncryptFuncAddr)encrypt_6,
        (pDecryptFuncAddr)decrypt_6,
        (pUpdateKeyFuncAddr)updatekey_3
    },
            //第b种
    {
        0xa3,
        0x1f,
        0x549,
        0x800,
        0x11,
        {0x68,0x00,0x10,0x00,0x08},
        0xf2,
        0x5,

        4,  //num waypoint
        {
            {0,FALSE,FALSE,0,{0},{0},{0},1,{"83 3c 24 ff"},{0}},
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 1, {"2C 4A"}, {1}},
            {3, FALSE,FALSE,1,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 03","66 c1 e9 04"},{2,3}},
            {4, FALSE,FALSE,0,{0},{0},{0},1,{"87 f1"},{4}}
        },
        7,
        TRUE,
        "8d 49 00",
        3,
        (pEncryptFuncAddr)encrypt_7,
        (pDecryptFuncAddr)decrypt_7,
        (pUpdateKeyFuncAddr)updatekey_4
    },
        //第c种
    {
        0xa6,
        0x20,
        0x549,
        0x800,
        0x11,
        {0x68,0x00,0x10,0x00,0x08},
        0xf2,
        0x5,

        3,  //num waypoint
        {
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 2, {"83 4B 14 FF","21 6B 14"}, {0,1}},
            {3, FALSE,FALSE,1,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 03","66 c1 e9 04"},{2,3}},
            {4, FALSE,FALSE,0,{0},{0},{0},1,{"87 f1"},{4}}
        },
        7,
        FALSE,       
        NULL,
        0,
        (pEncryptFuncAddr)encrypt_7,
        (pDecryptFuncAddr)decrypt_7,
        (pUpdateKeyFuncAddr)updatekey_4
    },
            //第d种
    {
        0x95,
        0xf,
        0x543,
        0x800,
        0x0,  //不需要, 这个变种Key不会迭代
        { 0xE8,0x4F ,0x03 ,0x00 ,0x00 ,0x83,0xEC ,0x20 ,0x8B ,0xFC ,0x6A ,0x08 ,0x33 ,0xC0},
        0x10e,
        0xe,

        3,  //num waypoint
        {
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 2, {"31 6b 13","83 E5 00"}, {0,1}},
            {3, FALSE,FALSE,2,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 02","66 c1 e9 04"},{2,3}},  //这里得第二次才跳
            {4, FALSE,FALSE,0,{0},{0},{0},1,{"87 f1"},{4}}
        },
        7,
        FALSE,       
        NULL,
        0,
        (pEncryptFuncAddr)encrypt_8,
        (pDecryptFuncAddr)decrypt_8,
        (pUpdateKeyFuncAddr)updatekey_5
    },

     //第e种
    {
        0xa3,
        0x1f,
        0x549,
        0x800,
        0x11,
        {0x68,0x00,0x10,0x00,0x08},
        0xf2,
        0x5,

        3,  //num waypoint
        {
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 1, {"21 6B 14","01 6B 14"}, {0,1}},  //0x24的, 还是得主要靠这两条区分..
            {3, FALSE,FALSE,1,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 03","66 c1 e9 04"},{2,3}},
            {4, FALSE,FALSE,0,{0},{0},{0},1,{"87 f1"},{4}}
        },
        7,
        TRUE,
        "8d 49 00",
        3,
        (pEncryptFuncAddr)encrypt_7,
        (pDecryptFuncAddr)decrypt_7,
        (pUpdateKeyFuncAddr)updatekey_4
    },

    //第f种
    {
        0x95,
        0x11,
        0x549,
        0x800,
        0x11,
        {0x68,0x00,0x10,0x00,0x08},
        0xf2,
        0x5,

        3,  //num waypoint
        {
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 2, {"0F C1 6C 24 20","BD"}, {0,1}},
            {3, FALSE,FALSE,1,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 03","66 c1 e9 04"},{2,3}},
            {4, FALSE,FALSE,0,{0},{0},{0},1,{"8b ce"},{4}}
        },
        7,
        FALSE,
        NULL,
        0,
        (pEncryptFuncAddr)encrypt_7,
        (pDecryptFuncAddr)decrypt_7,
        (pUpdateKeyFuncAddr)updatekey_4
    },

    //第0x10种
    {
        0xa7,
        0x9,
        0x55e,
        0x800,
        0x13,
        { 0xe9,0xf3,0x00,0x00,0x00 },
        0,
        5,
        5,
        {
            { 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 EC 0C" },{ 0 } },
            { 1, TRUE,  FALSE, 1,{ "0f 84","74" },{ 2,1 },{ 4,1 }, 3,{ "bd","87 6C 24 20","01 6C 24 24" },{ 1,2,3 } },       
            { 3, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 2,{ "66 C1 E9 03","8B 46 34" },{ 4,5 } },
            { 4, FALSE,TRUE, 0,{ 0 },{ 0 }, { 0 }, 0, { 0 }, { 0 } },
            { 6, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "66 0F 1F 40 00" },{ 6 } }, //nop word ptr [eax+00h]  
        },
        7,
        TRUE,
        "8d 49 00",    //lea ecx, [ecx+0]
        3,
        (pEncryptFuncAddr)encrypt_9,
        (pDecryptFuncAddr)decrypt_9,
        (pUpdateKeyFuncAddr)updatekey_2
    },

    //第0x11种
    {
        0x96,
        0x10,
        0x543,
        0x800,
        0x0,
        {0xeb,0x01,0xff,0xc7,0x04,0x24},
        0x0,
        0x6,

        3,  //num waypoint
        {
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 4, {"33 ed","81 ed","83 63 14 00","09 6b 14"}, {0,1,2,3}},
            {3, FALSE,FALSE,2,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 03","66 c1 e9 04"},{4,5}},
            {4, FALSE,FALSE,0,{0},{0},{0},1,{"87 f1"},{4}}
        },
        7,
        TRUE,       
        "8b ff",
        2,
        (pEncryptFuncAddr)encrypt_8,
        (pDecryptFuncAddr)decrypt_8,
        (pUpdateKeyFuncAddr)updatekey_5
    },
   
    //第0x12种
    {
        0x9e,
        0x17,
        0x549,
        0x800,
        0x11,
        { 0x83, 0xEC, 0x20, 0x8B, 0xFC, 0x6A, 0x08, 0x33, 0xC0, 0x59 },
        0x113,
        0xa,
        3,
        {
            { 1, TRUE,  TRUE, 1, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "8D 5C 24 0C","C7 43 14"}, {0,1} },        
            { 3, FALSE, FALSE, 1, {"0f 84","74"}, {2,1}, {4,1}, 3,{ "66 C1 E9 03","64 ff 30","0F A2" }, {2,3,4} },   
            { 4, FALSE, FALSE, 0, { 0 },{ 0 },{ 0 }, 1,{"87 F1"},{5}}
        },
        7,
        TRUE,
        "8d 49 00",    //lea ecx, [ecx+0]
        3,
        (pEncryptFuncAddr)encrypt_7,
        (pDecryptFuncAddr)decrypt_7,
        (pUpdateKeyFuncAddr)updatekey_4
    }

};


void updatekey_1(WORD* key, WORD dw_key_sig, WORD times)
{
    WORD temp = *key;
    __asm
    {
        pushfd
        pushad
        movzx eax, temp
        movzx ecx, times

fuck_1_u :
        imul dw_key_sig       
        xchg ah,al
        dec ecx
        jnz fuck_1_u

        mov temp, ax
        popad
        popfd
    }
    *key = temp;
}
void updatekey_2(WORD* key, WORD dw_key_sig, WORD times)
{
    WORD temp = *key;
    __asm
    {
        pushfd
        pushad
        movzx eax, temp
        movzx ecx, times

fuck_2_u :
        rol ax,4
        imul dw_key_sig
        dec ecx
        
        jnz fuck_2_u
        mov temp,ax
        popad
        popfd
    }
    *key = temp;
}
void updatekey_3(WORD* key, WORD dw_key_sig, WORD times)
{
    WORD temp = *key;
    __asm
    {
        pushfd
        pushad
        movzx eax, temp
        movzx ecx, times

fuck_3_u :
        xor al,ah
        imul dw_key_sig
        dec ecx
        
        jnz fuck_3_u
        mov temp,ax
        popad
        popfd
    }
    *key = temp;
}
void updatekey_4(WORD* key, WORD dw_key_sig, WORD times)
{
    WORD temp = *key;
    __asm
    {
        pushfd
        pushad
        movzx eax, temp
        movzx ecx, times

fuck_4_u :
        rol ax, 8
        imul dw_key_sig
        dec ecx
        
        jnz fuck_4_u
        mov temp,ax
        popad
        popfd
    }
    *key = temp;
}
void updatekey_5(WORD* key, WORD dw_key_sig, WORD times)
{
    ;  //什么都不干
}

//基本不同的算法之间只需要替换标号与jnz之间的段就行了. 标号得重新改名
void encrypt_1(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_1_e:
        xor byte ptr [eax],dl
        imul edx,dw_key_sig
        inc eax
        dec ecx
        xchg dh, dl
        jnz fuck_1_e

        popad
        popfd
    }
}
void decrypt_1(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_1_d :
        xor byte ptr [eax], dl
        imul edx, dw_key_sig
        inc eax
        dec ecx
        xchg dh, dl
        jnz fuck_1_d
		
        popad
        popfd
	}
}


void encrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_2_e:
        add [eax],dh
        imul edx,dw_key_sig
        xor [eax], dl
        inc eax
        dec ecx
        xchg dh, dl
        jnz fuck_2_e

        popad
        popfd
    }
}
void decrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_2_d :
        mov ebx, edx
        imul edx, dw_key_sig
        xor [eax], dl
        sub [eax], bh
        inc eax
        dec ecx
        xchg dh, dl
        jnz fuck_2_d
		
        popad
        popfd
	}
}


void encrypt_3(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_3_e:
        sub [eax], dh
        xor [eax], dl
        imul edx,dw_key_sig
        inc eax
        dec ecx
        xchg dh, dl
        jnz fuck_3_e

        popad
        popfd
    }
}
void decrypt_3(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_3_d :
        xor [eax], dl
        add [eax], dh
        imul edx, dw_key_sig
        inc eax
        dec ecx
        xchg dh, dl
        jnz fuck_3_d
		
        popad
        popfd
	}
}

void encrypt_4(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_4_e:
        xor [eax], dl
        rol dx, 4
        imul edx,dw_key_sig
        inc eax
        dec ecx
        jnz fuck_4_e

        popad
        popfd
    }
}
void decrypt_4(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_4_d :
        xor [eax], dl
        rol dx,4
        imul edx, dw_key_sig
        inc eax
        dec ecx
        jnz fuck_4_d
		
        popad
        popfd
	}
}

void encrypt_5(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_5_e:
        add [eax], dh
        xor [eax], dl
        imul edx,dw_key_sig
        inc eax
        dec ecx
        xchg dh, dl
        jnz fuck_5_e

        popad
        popfd
    }
}
void decrypt_5(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_5_d :
        xor [eax], dl
        sub [eax], dh
        imul edx, dw_key_sig
        inc eax
        dec ecx
        xchg dh, dl
        jnz fuck_5_d
		
        popad
        popfd
	}
}

void encrypt_6(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_6_e:
        sub [eax], dl
        xor dl,dh
        imul edx,dw_key_sig
        inc eax
        dec ecx
        jnz fuck_6_e

        popad
        popfd
    }
}
void decrypt_6(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_6_d :
        add [eax], dl
        xor dl,dh
        imul edx, dw_key_sig
        inc eax
        dec ecx
        jnz fuck_6_d
		
        popad
        popfd
	}
}

void encrypt_7(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_7_e:
        xor [eax], dl
        rol dx, 8
        imul edx,dw_key_sig
        inc eax
        dec ecx
        jnz fuck_7_e

        popad
        popfd
    }
}
void decrypt_7(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_7_d :
        xor [eax], dl
        rol dx, 8
        imul edx, dw_key_sig
        inc eax
        dec ecx
        jnz fuck_7_d
		
        popad
        popfd
	}
}


void encrypt_8(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_8_e:
        add [eax], dl
        xor [eax], dh
        inc eax
        dec ecx
        jnz fuck_8_e

        popad
        popfd
    }
}
void decrypt_8(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_8_d :
        xor [eax], dh
        sub [eax], dl
        inc eax
        dec ecx
        jnz fuck_8_d
		
        popad
        popfd
	}
}

void encrypt_9(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_9_e:
        rol dx, 4
        xor [eax], dl
        imul edx,dw_key_sig
        inc eax
        dec ecx
        jnz fuck_9_e

        popad
        popfd
    }
}
void decrypt_9(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_9_d :
        rol dx,4
        xor [eax], dl
        imul edx, dw_key_sig
        inc eax
        dec ecx
        jnz fuck_9_d
		
        popad
        popfd
	}
}
