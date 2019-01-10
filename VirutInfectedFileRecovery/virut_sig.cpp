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
			{0, FALSE, FALSE, 0, { 0 }, { 0 }, { 0 }, 1, {"83 3c 24 fe"}, {0}},         //cmp dword ptr[esp], -2
			{1, TRUE,  FALSE, 0, { 0 }, { 0 }, { 0 }, 1, {"68 4a 90 c5 01"}, {1}},      // push xx
			{2, FALSE, FALSE, 0, { 0 },{ 0 },{ 0 }, 1, {"89 74 24 44"}, {2}},         //mov [esp+44h],esi
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
			{ 1, TRUE,  FALSE, 1, {"0f 84","74"}, {2,1}, {4,1}, 1,{ "0f a2" }, {0} },         // jz  cpuid
			{ 3, FALSE, FALSE, 1, {"0f 84","74"}, {2,1}, {4,1}, 1,{ "66 C1 E9 03" }, {1} },   //jz   shr cx,3
			{ 4, FALSE, FALSE, 0, { 0 },{ 0 },{ 0 }, 2,{"8b ce","68 4c 13 79 60"},{2,3}}, //mov ecx,esi  push 6079134Ch
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
        4+1, 
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

        3+1,
        {
            {0,FALSE,FALSE, 0, {0}, {0}, {0}, 1, {"83 c4 e0"}, {0}},
            {1,TRUE,FALSE, 1, {"0f 84","74"},{2,1},{4,1}, 2, {"0F C1 6C 24 28","68 79 7F 7A F2"}, {1,2}},
            {4, FALSE, TRUE},
            {5, FALSE,FALSE,0,{ 0 },{ 0 },{ 0 }, 1, {"68 75 09 DA 1C"},{3}}
        },
        7,
        FALSE,
        NULL,
        0,
        (pEncryptFuncAddr)encrypt_6,
        (pDecryptFuncAddr)decrypt_6,
        (pUpdateKeyFuncAddr)updatekey_3
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
        xchg ah,al
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
        xchg dh, dl
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
        xchg dh, dl
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

