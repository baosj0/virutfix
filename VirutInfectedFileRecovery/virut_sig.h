#pragma once

#include <windows.h>

#define MAXKIND 8         //��ǰ����ı�������

struct waypoint
{
	BYTE nume8call;       //��Ч��·����
	BYTE bFollowIn;       //�Ƿ����e8call, �ǵĻ�������Ա��������
	BYTE num_jmpwhenmeet_specifiedtimes; //��������Ҫ���ĵ�ĸ���
	BYTE times[0x5];      //������ָ��ָ����ٴ�ʱ����
	CHAR sig[0x5][0x50];  //�������ָ����������ת��ָ��

	BYTE num_confirmed_sig;        //���ٸ���֤���
	char confirmed_sig[0x5][0x50]; //�����֤���
	BYTE confirmed_sig_index[0x5]; //ÿ����֤��Ƕ�Ӧ��index
};
typedef struct sig_struct
{
	WORD recover_off;
	WORD backvalue_off;
	WORD block_descript_offset;
	WORD dw_key_sig;
	BYTE db_before_sig[0x5];

	BYTE num_waypoint;  //�ò���β�ڴ�����ٸ�·����
	waypoint mypath[0x20];
	BYTE lastnume8call;
	BYTE bHasInstructionBeforeJmpBody;
	char LastInstructionBeforeJmpBody[0x50];

	DWORD pEncryptFuncAddr;  //���ܹ��̵ĺ�����ַ
	DWORD pDecryptFuncAddr;  //���ܹ��̵ĺ�����ַ

}*psig_struct;

sig_struct FuckedVirut[MAXKIND + 1] = { 0 };


//                                                     ����ûд��.
//                                      ����      1��    3��    2��    4��    5��    6��    7��    8��
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