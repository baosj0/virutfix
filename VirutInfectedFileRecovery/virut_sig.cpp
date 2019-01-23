#include "virut_sig.h"


sig_struct FuckedVirut[MAXKIND + 1] = 
{
    //第0种, 空着
    {
        0
    },
	//第1种变种标记赋值        对应的backvalue2指令可能有3条, add sub xor [esp+0x20].. 这个属于较早变种, 所以基本属性没变化, 这里我相当于把3代合在了一起.
	{
		0x173,
		0xe7,
		0xd,
        FALSE,
        NULL,
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

	//第2种变种标记赋值
	{
        0xb4,
        0xfa,
        0xefb5,
        TRUE,
        "FF E5",   //jmp ebp
        4 + 1,
        {
			{0, FALSE, FALSE, 0, { 0 }, { 0 }, { 0 }, 1, {"83 3c 24 fe"}, {0}},         //cmp dword ptr [esp], -2
			{1, TRUE,  TRUE, 0, { 0 }, { 0 }, { 0 }, 1, {"81 44 24 24"}, {1}},      // add dword ptr [esp+0x24], dd_backvalue2
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
	//第3种变种标记赋值
	{
		0xc2,
		0xfc,
		0x35,
        TRUE,
        "FF E5",
		4,
		{
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 ec 2c" }, {0} },         //sub esp,0x2c
			{ 1, TRUE,  TRUE, 0,{ 0 },{ 0 },{ 0 }, 3,{ "2B ED","81 CD","01 6B F8" }, {1,2,3} },  
			{ 3, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "65 FF 35 34 00 00 00" }, {4} },         //push gs:[0x34]
			{ 4, FALSE, TRUE },
		},
		7,
	    FALSE,
		NULL,
		0,
        (pEncryptFuncAddr)encrypt_3,
        (pDecryptFuncAddr)decrypt_3,
        (pUpdateKeyFuncAddr)updatekey_1
	},
	//第4种变种标记赋值
	{
		0xb5,
		0xfe,
		0xf1b3,
        TRUE,
        "ff e5",
		5,
		{
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 3c 24 ff" }, {0} },         // cmp dword ptr [esp],-1
			{ 1, TRUE,  TRUE, 0,{ 0 },{ 0 },{ 0 }, 2,{ "81 C5","87 6C 24 21" }, {1,2} },// add ebp, xx;  xchg ebp, [esp+21h]
			{ 2, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "89 74 24 44" }, {3} },         // mov [esp+44h],esi
            { 4, FALSE, TRUE},
			{ 6, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "f7 5c 24 04" }, {4} }			//neg dword ptr [esp + 4]
		},
		7,
		FALSE,
		NULL,
		0,
        (pEncryptFuncAddr)encrypt_2,
        (pDecryptFuncAddr)decrypt_2,
        (pUpdateKeyFuncAddr)updatekey_1
	},
	//第5种变种标记赋值
	{
		0xb4,
		0xfa,
		0xfb7f,
        TRUE,
        "FF E5",
        4,
        {
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "8d 64 24 d0" }, {0} },         // lea esp, [esp-0x30]
			{ 1, TRUE,  TRUE, 0,{ 0 },{ 0 },{ 0 }, 2,{ "81 C5","87 6C 24 21" }, {1,2} },			// 
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
		0x3fb,
        TRUE,
        "FF E0",
		4,
		{
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 ec 30" }, {0} },         // sub esp,0x30
			{ 1, TRUE,  FALSE, 0,{ 0 },{ 0 },{ 0 }, 3,{ "2B ED","81 F5","0F C1 69 FE" }, {1,2,3} },	// movzx edx,word ptr [ebx+1cbch]
		    { 4, FALSE, TRUE },
			{ 6, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "f7 54 24 04" }, {4} }			//not [esp+4]
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
        0xefb5,
        TRUE,
        "FF E5",   //jmp ebp
        4 + 1,
        {
			{0, FALSE, FALSE, 0, { 0 }, { 0 }, { 0 }, 1, {"83 3c 24 fe"}, {0}},         //cmp dword ptr [esp], -2
			{1, TRUE,  TRUE, 0, { 0 }, { 0 }, { 0 }, 1, {"81 44 24 24"}, {1}},      // add dword ptr [esp+0x24], dd_backvalue2
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
    //第八种变种标记赋值
    {
        0x9f,
        0x8,
        0x11,
        FALSE,
        NULL,
        3,
        {
            { 1, TRUE,  FALSE, 1, {"0f 84","74"}, {2,1}, {4,1}, 3,{ "0f a2","bd","0F C1 6C 24 20", }, {0,1,2} },         // jz  cpu
            { 3, FALSE, FALSE, 1, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "66 C1 E9 03","64 ff 36" }, {3,4} },   
            { 4, FALSE, FALSE, 0, { 0 },{ 0 },{ 0 }, 1,{"8b ce"},{5}}, //mov ecx,esi
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
        0x3d,
        TRUE,
        "FF E5",
        4,
        {
            { 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 ec 2c" }, {0} },  //sub esp, 2ch
            { 1, TRUE,  TRUE, 0,{ 0 },{ 0 },{ 0 }, 4,{ "2B ED","81 F5","87 2B","01 2b" }, {1,2,3,4} },  
            { 4, FALSE, TRUE },
            { 6, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "F7 54 24 04" }, {5} }  //not [esp+4h]
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
        0x17,
        FALSE,
        NULL,
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
        0x11,
        FALSE,
        NULL,
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
        0x11,
        FALSE,
        NULL,
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
        0x0,  //不需要, 这个变种Key不会迭代
        FALSE,
        NULL,
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
        0x11,
        FALSE,
        NULL,
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
        0x11,
        FALSE,
        NULL,
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
        0x13,
        FALSE,
        NULL,
        5,
        {
            { 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 EC 0C" },{ 0 } },
            { 1, TRUE,  FALSE, 1,{ "0f 84","74" },{ 2,1 },{ 4,1 }, 3,{ "bd","87 6C 24 20","01 6C 24 24" },{ 1,2,3 } },
            { 3, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 2,{ "66 C1 E9 03","8B 46 34" },{ 4,5 } },
            { 4, FALSE,TRUE },
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
        0x0,
        FALSE,
        NULL,
        3,  //num waypoint
        {
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 4, {"33 ed","81 ed","83 63 14 00","09 6b 14"}, {0,1,2,3}},
            {3, FALSE,FALSE,2,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 03","66 c1 e9 04"},{4,5}},
            {4, FALSE,FALSE,0,{0},{0},{0},1,{"87 f1"},{6}}
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
        0x11,
        FALSE,
        NULL,
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
    },
    
    //第0x13种
    {
        0x9c,
        0x15,
        0x11,
        FALSE,
        NULL,
        3,
        {
            { 1, TRUE,  TRUE, 1, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "81 6C 24","C6 04 24 00"}, {0,1} },        
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
    },
    //第0x14种
    {
        0x9b,
        0x17,
        0x11,
        FALSE,
        NULL,
        3,  //num waypoint
        {
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 1, {"81 6B 13"}, {0}},
            {3, FALSE,FALSE,1,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 03","66 c1 e9 04"},{1,2}},
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
    //第0x15种
    {
        0x9b,
        0x17,
        0x11,
        FALSE,
        NULL,
        3,  //num waypoint
        {
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 1, {"81 6B 13"}, {0}},
            {3, FALSE,FALSE,1,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 03","66 c1 e9 04"},{1,2}},
            {4, FALSE,FALSE,0,{0},{0},{0},1,{"87 f1"},{4}}
        },
        7,
        TRUE,
        "8D 49 00",
        3,
        (pEncryptFuncAddr)encrypt_7,
        (pDecryptFuncAddr)decrypt_7,
        (pUpdateKeyFuncAddr)updatekey_4
    },
    //第0x16种
    {
        0xa6,
        0x9,
        0x13,
        FALSE,
        NULL,
        5,
        {
            { 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 EC 0C" },{ 0 } },
            { 1, TRUE,  FALSE, 1,{ "0f 84","74" },{ 2,1 },{ 4,1 }, 3,{ "bd","87 6C 24 20","01 6C 24 20" },{ 1,2,3 } },       
            { 3, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 2,{ "66 C1 E9 03","8B 46 34" },{ 4,5 } },
            { 4, FALSE,TRUE },
            { 6, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "66 0F 1F 40 00" },{ 6 } }, //nop word ptr [eax+00h]  
        },
        7,
        FALSE,
        NULL,
        0,
        (pEncryptFuncAddr)encrypt_9,
        (pDecryptFuncAddr)decrypt_9,
        (pUpdateKeyFuncAddr)updatekey_2
    },
    //第0x17种
    {
        0xac,
        0x9,
        0x13,
        FALSE,
        NULL,
        5,
        {
            { 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 EC 0C" },{ 0 } },
            { 1, TRUE,  FALSE, 1,{ "0f 84","74" },{ 2,1 },{ 4,1 }, 2,{ "bd","87 6C 24 20" },{ 1,2 } },
            { 2, FALSE, FALSE, 0,{0},{0},{0},1,{"01 6C 24 20"},{3}},
            { 3, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 2,{ "66 C1 E9 02","8B 47 34" },{ 4,5 } },
            { 4, FALSE,TRUE }        
        },
        7,
        TRUE,
        "8b ff",
        2,
        (pEncryptFuncAddr)encrypt_a,
        (pDecryptFuncAddr)decrypt_a,
        (pUpdateKeyFuncAddr)updatekey_6
    },
    //第0x18种
    {
        0xa4,
        0xb2,
        0x17,
        TRUE,
        "FF 64 24 24",
        3 + 1,
        {
            {0,FALSE,FALSE, 0, {0}, {0}, {0}, 1, {"83 c4 e0"}, {0}},
            {1,TRUE,TRUE, 1, {"0f 84","74"},{2,1},{4,1}, 2, {"BD","0F C1 6C 24 24"}, {1,2}},
            {4, FALSE, TRUE},
            {6, FALSE,FALSE,0,{ 0 },{ 0 },{ 0 }, 2, {"6a 01","6a ff"},{3,4}}
        },
        7,
        TRUE,
        "8D 49 00",
        3,
        (pEncryptFuncAddr)encrypt_b,
        (pDecryptFuncAddr)decrypt_b,
        (pUpdateKeyFuncAddr)updatekey_7
    },
    //第0x19种
    {
        0xa7,
        0x9,
        0x13,
        FALSE,
        NULL,
        5,
        {
            { 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "83 EC 0C" },{ 0 } },
            { 1, TRUE,  FALSE, 1,{ "0f 84","74" },{ 2,1 },{ 4,1 }, 2,{ "bd","87 6C 24 20"},{ 1,2 } },
            { 2, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "01 6C 24 20" },{ 3 } },
            { 3, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 2,{ "66 C1 E9 03","8B 46 34" },{ 4,5 } },
            { 4, FALSE,TRUE }              
        },
        7,
        TRUE,
        "8d 49 00",    //lea ecx, [ecx+0]
        3,
        (pEncryptFuncAddr)encrypt_9,
        (pDecryptFuncAddr)decrypt_9,
        (pUpdateKeyFuncAddr)updatekey_2
    },
    //第0x1a种
    {
        0xa2,
        0x1e,
        0x11,
        FALSE,
        NULL,
        3,  //num waypoint
        {
            {1, TRUE, TRUE, 1, {"0F 84", "74"}, {2,1},{4,1}, 4, {"33 ed","81 ed","21 6B 14","09 6b 14"}, {0,1,2,3}},
            {3, FALSE,FALSE,1,{"0f 84","74"},{2,1},{4,1},2,{"66 c1 e9 03","66 c1 e9 04"},{4,5}},
            {4, FALSE,FALSE,0,{0},{0},{0},1,{"87 f1"},{6}}
        },
        7,
        TRUE,       
        "90",  //第一次见到nop..
        1,
        (pEncryptFuncAddr)encrypt_7,
        (pDecryptFuncAddr)decrypt_7,
        (pUpdateKeyFuncAddr)updatekey_4
    },
    //第1b种
    {
        0xae,
        0xbc,
        0x17,
        TRUE,
        "FF 64 24 34",
        2 + 1,
        {
            {0,FALSE,FALSE, 0, {0}, {0}, {0}, 1, {"83 c4 e0"}, {0}},
            {1,TRUE,TRUE, 1, {"0f 84","74"},{2,1},{4,1}, 2, {"BD","0F C1 6C 24 34"}, {1,2}},
            {4, FALSE, TRUE}
        },
        9,
        TRUE,
        "8d 49 00",
        3,
        (pEncryptFuncAddr)encrypt_6,
        (pDecryptFuncAddr)decrypt_6,
        (pUpdateKeyFuncAddr)updatekey_3
    },
    //第1c种
    {
        0xae,
        0xbc,
        0x17,
        TRUE,
        "FF 64 24 30",
        2 + 1,
        {
            {0,FALSE,FALSE, 0, {0}, {0}, {0}, 1, {"83 c4 e0"}, {0}},
            {1,TRUE,TRUE, 1, {"0f 84","74"},{2,1},{4,1}, 2, {"BD","0F C1 6C 24 30"}, {1,2}},
            {4, FALSE, TRUE}
        },
        9,
        TRUE,
        "8d 49 00",
        3,
        (pEncryptFuncAddr)encrypt_6,
        (pDecryptFuncAddr)decrypt_6,
        (pUpdateKeyFuncAddr)updatekey_3
    },
    //第1d种
    {
        0xa8,
        0xb6,
        0x17,
        TRUE,
        "FF 64 24 30",
        2 + 1,
        {
            {0,FALSE,FALSE, 0, {0}, {0}, {0}, 1, {"83 c4 e0"}, {0}},
            {1,TRUE,TRUE, 1, {"0f 84","74"},{2,1},{4,1}, 2, {"BD","0F C1 6C 24 30"}, {1,2}},
            {4, FALSE, TRUE}
        },
        9,
        TRUE,
        "90",
        1,
        (pEncryptFuncAddr)encrypt_6,
        (pDecryptFuncAddr)decrypt_6,
        (pUpdateKeyFuncAddr)updatekey_3
    },
    //第1e种
    {
        0xa8,
        0xb6,
        0x17,
        TRUE,
        "FF 64 24 30",
        2 + 1,
        {
            {0,FALSE,FALSE, 0, {0}, {0}, {0}, 1, {"83 c4 e0"}, {0}},
            {1,TRUE,TRUE, 1, {"0f 84","74"},{2,1},{4,1}, 2, {"BD","0F C1 6C 24 30"}, {1,2}},
            {4, FALSE, TRUE}
        },
        8,
        TRUE,
        "90",
        1,
        (pEncryptFuncAddr)encrypt_6,
        (pDecryptFuncAddr)decrypt_6,
        (pUpdateKeyFuncAddr)updatekey_3
    },
    //第1f种
    {
        0xa8,
        0xb6,
        0x17,
        TRUE,
        "FF 64 24 30",
        2 + 1,
        {
            {0,FALSE,FALSE, 0, {0}, {0}, {0}, 1, {"83 c4 e0"}, {0}},
            {1,TRUE,TRUE, 1, {"0f 84","74"},{2,1},{4,1}, 2, {"BD","0F C1 6C 24 30"}, {1,2}},
            {4, FALSE, TRUE}
        },
        8,
        TRUE,
        "8D 49 00",
        3,
        (pEncryptFuncAddr)encrypt_6,
        (pDecryptFuncAddr)decrypt_6,
        (pUpdateKeyFuncAddr)updatekey_3
    },
    //第0x20种
    {
		0xa2,
		0xf,
		0xd,
        FALSE,
        NULL,
        2,
        {
			{ 1, TRUE,  TRUE,  1, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "68","8F 44 24 20"},{ 0,1 } },    
			{ 4, FALSE, FALSE, 2, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "66 8C CA","66 C1 EA 05" },{ 3,4 } },     
        },
        8,
        TRUE,
        "8B FF", 
        2,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},
    //第0x21种
    {
		0x9a,
		0xb,
		0xd,
        FALSE,
        NULL,
        2,
        {
			{ 1, TRUE,  TRUE,  1, {"0f 84","74"}, {2,1}, {4,1}, 3,{ "8D 5C 24 04","bd","87 6B 1C" },{ 0,1,2 } },         
			{ 4, FALSE, FALSE, 2, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "66 8C CA","66 C1 EA 05" },{ 3,4 } },     
        },
        8,
        TRUE,
        "8B FF", 
        2,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},

    //第0x22种
    {
		0x9a,
		0xb,
		0xd,
        FALSE,
        NULL,
        2,
        {
			{ 1, TRUE,  TRUE,  1, {"0f 84","74"}, {2,1}, {4,1}, 3,{ "8D 5C 24 04","BD","87 6B 1C"},{ 0,1,2 } },    
			{ 4, FALSE, FALSE, 2, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "66 8C CA","66 C1 EA 05" },{ 3,4 } },     
        },
        8,
        TRUE,
        "8B FF", 
        2,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},

    //第0x23种
	{
		0xa6,
		0xe,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "8D 5C 24 10","2B ED","81 ED","87 6B 10" }, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"8d 49 00",
		3,
        (pEncryptFuncAddr)encrypt_c,
        (pDecryptFuncAddr)decrypt_c,
        (pUpdateKeyFuncAddr)updatekey_5
	},
    //第0x24种
	{
		0xa7,
		0xe,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "8D 5C 24 10","2B ED","81 ED","87 6C 24 20" }, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"90",
		1,
        (pEncryptFuncAddr)encrypt_c,
        (pDecryptFuncAddr)decrypt_c,
        (pUpdateKeyFuncAddr)updatekey_5
	},
    //第0x25种
	{
		0xa1,
		0xe,
		0xd,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "33 ED","8D 5C 24 04","81 C5","87 6B 1C" }, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"8D 49 00",
		3,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},
    //第0x26种
	{
		0xa2,
		0xd,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "2B C0","8D 5C 24 10","05","87 43 10" }, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"8D 49 00",
		3,
        (pEncryptFuncAddr)encrypt_c,
        (pDecryptFuncAddr)decrypt_c,
        (pUpdateKeyFuncAddr)updatekey_5
	},
    //第0x27种
	{
		0xa4,
		0xd,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "2B C0","8D 5C 24 10","05","87 43 10" }, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"90",
		1,
        (pEncryptFuncAddr)encrypt_c,
        (pDecryptFuncAddr)decrypt_c,
        (pUpdateKeyFuncAddr)updatekey_5
	},
    //第0x28种
	{
		0xa1,
		0x9,
		0xd,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 3,{ "8B DC","68","8F 43 20"}, {0,1,2} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"8D 49 00",
		3,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},

	//第0x29种
	{
		0xa7,
		0xe9,
		0x55d,
        TRUE,
        "FF E5",
        4,
        {
			{ 0, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 2,{ "83 EC 30","83 C4 24" }, {0,1} },         
			{ 1, TRUE,  TRUE, 0,{ 0 },{ 0 },{ 0 }, 2,{ "8B 2C 24","81 C5" }, {2,3} },			
            { 4, FALSE, TRUE },
			{ 6, FALSE, FALSE, 0,{ 0 },{ 0 },{ 0 }, 1,{ "f7 5c 24 04" }, {4} } 
        },
        7,
        FALSE,
        NULL,  
        0,
        (pEncryptFuncAddr)encrypt_2,
        (pDecryptFuncAddr)decrypt_2,
        (pUpdateKeyFuncAddr)updatekey_1
	},

	//第0x2a种
	{
		0x9a,
		0xb,
		0xd,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 3,{ "8D 5C 24 04","BD","87 6B 1C"}, {0,1,2} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"90",
		1,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},
	//第0x2b种
	{
		0xa1,
		0x12,
		0xd,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 1,{ "C7 44 24 20"}, {0} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    FALSE,
		NULL,
		0,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},
	//第0x2c种
	{
		0xa0,
		0xa,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "33 ED","81 C5","8D 5C 24 08","87 6B 18"}, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"8b ff",
		2,
        (pEncryptFuncAddr)encrypt_e,
        (pDecryptFuncAddr)decrypt_e,
        (pUpdateKeyFuncAddr)updatekey_8
	},
	//第0x2d种
	{
		0xa2,
		0xa,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "33 ED","81 C5","8D 5C 24 04","87 6B 1C"}, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    FALSE,
		NULL,
		0,
        (pEncryptFuncAddr)encrypt_e,
        (pDecryptFuncAddr)decrypt_e,
        (pUpdateKeyFuncAddr)updatekey_8
	},
	//第0x2e种
	{
		0x9f,
		0xa,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "33 ED","81 C5","8B DC","87 6B 20"}, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"90",
		1,
        (pEncryptFuncAddr)encrypt_e,
        (pDecryptFuncAddr)decrypt_e,
        (pUpdateKeyFuncAddr)updatekey_8
	},
	//第0x2f种
	{
		0xa6,
		0xe,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "2B ED","81 ED","8D 5C 24 10","87 6B 10"}, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"8B FF",
		2,
        (pEncryptFuncAddr)encrypt_c,
        (pDecryptFuncAddr)decrypt_c,
        (pUpdateKeyFuncAddr)updatekey_5
	},
	//第0x30种
	{
		0x9f,
		0x12,
		0xd,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 1,{ "81 74 24 20"}, {0} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"8B FF",
		2,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},
	//第0x31种
	{
		0xa3,
		0xe,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "33 ED","8D 5C 24 04","81 CD","87 6B 1C"}, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    FALSE,
		NULL,
		0,
        (pEncryptFuncAddr)encrypt_e,
        (pDecryptFuncAddr)decrypt_e,
        (pUpdateKeyFuncAddr)updatekey_8
	},
	//第0x32种
	{
		0xa2,
		0xe,
		0x0,
        FALSE,
        NULL,
		2,
		{
			{ 1, TRUE,  TRUE, 1,{ "0f 84","74" },{2,1  },{ 4,1 }, 4,{ "2B ED","8D 5C 24 10","81 C5","87 6B 10"}, {0,1,2,3} },  
			{ 4, FALSE, FALSE, 2,{ "0f 84","74" },{ 2,1 },{ 4,1 } }
		},
		8,
	    TRUE,
		"8B FF",
		2,
        (pEncryptFuncAddr)encrypt_f,
        (pDecryptFuncAddr)decrypt_f,
        (pUpdateKeyFuncAddr)updatekey_5
	},
    //第0x33种
	{
		0x172,
		0xe5,
		0xd,
        FALSE,
        NULL,
        2,
        {
			{ 1, TRUE,  TRUE,  1, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "8b 6c 24 20","80 3B 4D" },{ 0,1 } },         // jz; mov ebp, [esp+0x20]; cmp byte ptr [ebx], 4Dh 
			{ 4, FALSE, FALSE, 2, {"0f 84","74"}, {2,1}, {4,1}, 2,{ "66 8c ca","66 c1 ea 05" },{ 2,3 } },         // jz; mov ax, cs; shr ax,5
        },
        8,
        TRUE,
        "90",    //nop
        1,
        (pEncryptFuncAddr)encrypt_1,
        (pDecryptFuncAddr)decrypt_1,
        (pUpdateKeyFuncAddr)updatekey_1
	},
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
void updatekey_6(WORD* key, WORD dw_key_sig, WORD times)
{
    WORD temp = *key;
    __asm
    {
        pushfd
        pushad
        movzx eax, temp
        movzx ecx, times

fuck_6_u :
        rol ax, 5
        imul dw_key_sig
        dec ecx
        
        jnz fuck_6_u
        mov temp,ax
        popad
        popfd
    }
    *key = temp;
}
void updatekey_7(WORD* key, WORD dw_key_sig, WORD times)
{
    WORD temp = *key;
    __asm
    {
        pushfd
        pushad
        movzx eax, temp
        movzx ecx, times

fuck_7_u :
        xor eax, 3
        imul dw_key_sig
        dec ecx
        
        jnz fuck_7_u
        mov temp,ax
        popad
        popfd
    }
    *key = temp;
}
void updatekey_8(WORD* key, WORD dw_key_sig, WORD times)
{
    WORD temp = *key;
    __asm
    {
        pushfd
        pushad
        movzx eax, temp
        movzx ecx, times

fuck_8_u :
        xchg ah,al
        dec ecx
        
        jnz fuck_8_u
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

void encrypt_a(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_a_e:
        sub [eax],dl
        rol dx,5
        imul edx,dw_key_sig
        inc eax
        dec ecx
        jnz fuck_a_e

        popad
        popfd
    }
}
void decrypt_a(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_a_d :
        add [eax], dl
        rol dx,5    
        imul edx, dw_key_sig
        inc eax
        dec ecx
        jnz fuck_a_d
		
        popad
        popfd
	}
}

void encrypt_b(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_b_e:
        sub [eax],dl
        xor edx,3
        imul edx,dw_key_sig
        inc eax
        dec ecx
        jnz fuck_b_e

        popad
        popfd
    }
}
void decrypt_b(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_b_d :
        add [eax], dl
        xor edx,3    
        imul edx, dw_key_sig
        inc eax
        dec ecx
        jnz fuck_b_d
		
        popad
        popfd
	}
}

void encrypt_c(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_c_e:
        xor [eax], dh
        add [eax], dl       
        inc eax
        dec ecx
        jnz fuck_c_e

        popad
        popfd
    }
}
void decrypt_c(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_c_d :
        sub [eax], dl
        xor [eax], dh
        inc eax
        dec ecx
        jnz fuck_c_d
		
        popad
        popfd
	}
}

void encrypt_d(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_d_e:
        xor [eax], dl
        imul edx, dw_key_sig
        xchg dh,dl
        inc eax
        dec ecx
        jnz fuck_d_e

        popad
        popfd
    }
}
void decrypt_d(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_d_d :
        xor [eax], dl
        imul edx, dw_key_sig
        xchg dh,dl
        inc eax
        dec ecx
        jnz fuck_d_d
		
        popad
        popfd
	}
}

void encrypt_e(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_e_e:
        xor [eax], dh
        xchg dh,dl
        inc eax
        dec ecx
        jnz fuck_e_e

        popad
        popfd
    }
}
void decrypt_e(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_e_d :
        xor [eax], dh
        xchg dh,dl
        inc eax
        dec ecx
        jnz fuck_e_d
		
        popad
        popfd
	}
}

void encrypt_f(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad
        movzx dx,key
        mov eax,data
        movzx ecx,decryptsize

fuck_f_e:
        sub [eax], dl
        xor [eax], dh
        inc eax
        dec ecx
        jnz fuck_f_e

        popad
        popfd
    }
}
void decrypt_f(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize)
{
    __asm
    {
        pushfd
        pushad

        movzx dx, key
        mov eax, data
        movzx ecx, decryptsize

fuck_f_d :
        xor [eax], dh
        add [eax], dl
        inc eax
        dec ecx
        jnz fuck_f_d
		
        popad
        popfd
	}
}

BOOL getCFbyte(BYTE b1, BYTE b2, BOOL cf)
{
    BYTE sum = b1 + b2 + cf;
    return sum < b1;
}
BOOL getCFword(WORD w1, WORD w2, BOOL cf)
{
    WORD sum = w1 + w2 + cf;
    return sum < w1;
}
BOOL getCFdword(DWORD d1, DWORD d2, BOOL cf)
{
    DWORD sum = d1 + d2 + cf;
    return sum < d1;
}

BOOL getCFbyte_sbb(BYTE b1, BYTE b2, BOOL cf)
{
    return b1 < b2 + cf;
}
BOOL getCFword_sbb(WORD w1, WORD w2, BOOL cf)
{
    return w1 < w2 + cf;
}
BOOL getCFdword_sbb(DWORD d1, DWORD d2, BOOL cf)
{
    return d1 < d2 + cf;
}



int last_before_off = 0;
int last_before_off_index = 0;
int last_before_sig = 0;

int last_crack_method = 0;

int num_off = 0x8;
int num_sig = 0x2;
int lastvirutkind = 1;
const BYTE before_sig[0x10][0x20] =             //0x11代表可变数据, 匹配的时候随便
{
  { 0xC7, 0x04, 0x24, 0x11, 0x11, 0x11, 0x11, 0xE8, 0x11, 0x11,
    0x11, 0x11, 0x56, 0x8B, 0x95, 0x11, 0x11, 0x11, 0x11, 0xE8,
    0x00, 0x00, 0x00, 0x00 },
  { 0x68, 0x11, 0x11, 0x11, 0x11, 0xE8, 0x11, 0x11,
    0x11, 0x11, 0x56, 0x8B, 0x95, 0x11, 0x11, 0x11, 0x11, 0xE8,
    0x00, 0x00, 0x00, 0x00 }
};

int before_len[0x10] = { 0x18, 0x16 };
int before_off_array[0x10] =
{
    0x3, 0xf8, 0x115, 0x132, 0xe2, 0x5, 0x2, 0x0       //按目前出现的频率, 从高到低排列
};