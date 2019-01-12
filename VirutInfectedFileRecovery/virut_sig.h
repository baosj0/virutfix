#pragma once

#include <windows.h>

#define MAXKIND 18        //��ǰ����ı�������

typedef void (*pEncryptFuncAddr)(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
typedef void (*pDecryptFuncAddr)(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
typedef void (*pUpdateKeyFuncAddr)(WORD* key, WORD dw_key_sig, WORD times);

struct waypoint
{
	BYTE nume8call;       //��Ч��·����, ÿ��virut����ֻ����һ��ͬnume8call��waypoint         ��0��ʼ
	BYTE bGenBackValue1;  //�Ƿ�Ϊ����backvalue1��ֵ������callָ��     ����ж���pLastCode+iΪ0xe8ʱ��
	BYTE bFollowIn;       //�Ƿ����e8call,                           ����ж���pLastCode+iΪ0xe8ʱ��
	BYTE times;      //������ָ��ָ����ٴ�ʱ����                    //��1��ʼ, ����, ����jz һ��
	const CHAR *sig[2];  //�������ָ����������ת��ָ��
	BYTE off_jmpvalue[2]; //��Ӧ��תָ����ת����ֵ  ����ָ�ʼ��ƫ��
	BYTE size_jmpvalue[2];//��Ӧ��תָ����ת����ֵ���ֽڴ�С

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
	BYTE db_before_sig[0x10];
    WORD db_before_sig_offset_from_body;
    BYTE db_before_sig_len;

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

//��Щ�ӽ�����ʵ��һ���ĺ���, ���һ���д������

//virutkind 1 2 3 4 5 6 7 �ĵ���key��ʽ
extern void updatekey_1(WORD* key, WORD dw_key_sig, WORD times);

//virutkind 8  �ĵ���key��ʽ
extern void updatekey_2(WORD* key, WORD dw_key_sig, WORD times);

//virutkind a
extern void updatekey_3(WORD* key, WORD dw_key_sig, WORD times);

//virutkind b c e f 12
extern void updatekey_4(WORD* key, WORD dw_key_sig, WORD times);

//virutkind d 11
extern void updatekey_5(WORD* key, WORD dw_key_sig, WORD times);


//virutkind 1 �ļӽ�����غ���
extern void encrypt_1(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_1(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 2 4 5 6 7 �ļӽ�����غ���
extern void encrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);


//virutkind 3 �ļӽ�����غ���
extern void encrypt_3(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_3(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 8 �ļӽ�����غ���
extern void encrypt_4(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_4(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 9
extern void encrypt_5(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_5(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind a
extern void encrypt_6(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_6(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind b c e f 12
extern void encrypt_7(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_7(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind d 11
extern void encrypt_8(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_8(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 10
extern void encrypt_9(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_9(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
