#pragma once

#include <windows.h>

#define MAXKIND 8         //��ǰ����ı�������

typedef void(*pEncryptFuncAddr)(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
typedef void(*pDecryptFuncAddr)(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
typedef void(*pUpdateKeyFuncAddr)(WORD* key, WORD dw_key_sig, WORD times);

struct waypoint
{
	BYTE nume8call;       //��Ч��·����, ÿ��virut����ֻ����һ��ͬnume8call��waypoint         ��0��ʼ
	BYTE bGenBackValue1;  //�Ƿ�Ϊ����backvalue1��ֵ������callָ��     ����ж���pLastCode+iΪ0xe8ʱ��
	BYTE bFollowIn;       //�Ƿ����e8call, �ǵĻ�������Ա��������     ����ж���pLastCode+iΪ0xe8ʱ��
	BYTE times;      //������ָ��ָ����ٴ�ʱ����                    //��1��ʼ, ����, ����jz һ��
	const CHAR *sig;  //�������ָ����������ת��ָ��
	BYTE off_jmpvalue; //��Ӧ��תָ����ת����ֵ  ����ָ�ʼ��ƫ��
	BYTE size_jmpvalue;//��Ӧ��תָ����ת����ֵ���ֽڴ�С

	BYTE num_confirmed_sig;        //���ٸ���֤���
	const char *confirmed_sig[0x5]; //�����֤���
	BYTE confirmed_sig_index[0x5]; //ÿ����֤��Ƕ�Ӧ��index
};
typedef struct sig_struct
{
	WORD recover_off;
	WORD backvalue_off;
	WORD block_descript_offset;
	WORD block_descript_size;
	WORD dw_key_sig;
	BYTE db_before_sig[0x5];

	BYTE num_waypoint;  //�ò���β�ڴ�����ٸ�·����
	waypoint mypath[0x20];                          //�����Ԫ��, nume8call��С������Ψһ
	BYTE lastnume8call;
	BYTE bHasInstructionBeforeJmpBody;
	const char *LastInstructionBeforeJmpBody;
	BYTE LastInstructionSize;

	pEncryptFuncAddr EncryptFunc; //���ܹ��̵ĺ���
	pDecryptFuncAddr DecryptFunc; //���ܹ��̵ĺ���
	pUpdateKeyFuncAddr UpdateKey; //��key�ü����㷨����ָ������, ���ָ��λ��ʱ��key

}*psig_struct;

extern sig_struct FuckedVirut[MAXKIND + 1];

//virutkind 2 4 5 6 7 �ļӽ�����غ���
extern void encrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void updatekey_2(WORD* key, WORD dw_key_sig, WORD times);

