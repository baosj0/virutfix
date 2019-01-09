#pragma once

#include <windows.h>

#define MAXKIND 8         //当前处理的变种数量

struct waypoint
{
	BYTE nume8call;       //生效的路径段
	BYTE bFollowIn;       //是否跟进e8call, 是的话后续成员均无意义
	BYTE num_jmpwhenmeet_specifiedtimes; //本段中需要跳的点的个数
	BYTE times[0x5];      //当遇到指定指令多少次时才跳
	CHAR sig[0x5][0x50];  //存放碰到指定次数就跳转的指令

	BYTE num_confirmed_sig;        //多少个验证标记
	char confirmed_sig[0x5][0x50]; //存放验证标记
	BYTE confirmed_sig_index[0x5]; //每个验证标记对应的index
};
typedef struct sig_struct
{
	WORD recover_off;
	WORD backvalue_off;
	WORD block_descript_offset;
	WORD dw_key_sig;
	BYTE db_before_sig[0x5];

	BYTE num_waypoint;  //该病毒尾节代码多少个路径点
	waypoint mypath[0x20];
	BYTE lastnume8call;
	BYTE bHasInstructionBeforeJmpBody;
	char LastInstructionBeforeJmpBody[0x50];

	DWORD pEncryptFuncAddr;  //加密过程的函数地址
	DWORD pDecryptFuncAddr;  //解密过程的函数地址

}*psig_struct;

sig_struct FuckedVirut[MAXKIND + 1] = { 0 };


//                                                     这里没写反.
//                                      闲置      1代    3代    2代    4代    5代    6代    7代    8代
//              virutkind                  0      1      2      3      4      5      6      7      8
WORD recover_off[MAXKIND + 1] = { 0x0000,0x0173,0x00b4,0x00c2,0x00b5,0x00b4,0x00b5,0x00b4,0x009f };
WORD backvalue_off[MAXKIND + 1] = { 0x0000,0x0000,0x00fa,0x00fc,0x00fe,0x00fa,0x00f9,0x00fa,0x0008 };

int blockdescript_offset[MAXKIND + 1] = { 0x0000,0x0000,0x059e,0x05a1,0x05b1,0x05ab,0x05a1,0x0594,0x0548 };
WORD dw_key_sig[MAXKIND + 1] = { 0x0000,0x0000,0xefb5,0x0035,0xf1b3,0xfb7f,0x03fb,0xefb5,0x0011 };
BYTE db_before_sig[MAXKIND + 1][5] =
{
	{ 0 },
{ 0 },
{ 0xe9,0x10,0x01,0x00,0x00 },
{ 0xe9,0x2d,0x01,0x00,0x00 },
{ 0xe9,0x2d,0x01,0x00,0x00 },
{ 0xe9,0x2d,0x01,0x00,0x00 },
{ 0xe9,0x2d,0x01,0x00,0x00 },
{ 0xe9,0x10,0x01,0x00,0x00 },
{ 0xe9,0xdd,0x00,0x00,0x00 }
};