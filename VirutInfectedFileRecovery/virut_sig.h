#pragma once

#include <windows.h>

#define MAXKIND 43       //��ǰ����ı�������

#define rol( a , o ) \
((a<<(o%0x20)) | (a>>(0x20 - (o%0x20))))
#define ror( a , o ) \
((a>>(o%0x20)) | (a<<(0x20 - (o%0x20))))

#define BLOCKOFF_MIN  0x500
#define BLOCKSIZE_MAX 0xa00
#define BLOCKNUM_MAX 0x100

#define BODYSIZE_MIN 0x3000
#define BODYSIZE_MAX 0x9000



extern BOOL getCFbyte(BYTE b1, BYTE b2, BOOL cf);
extern BOOL getCFword(WORD w1, WORD w2, BOOL cf);
extern BOOL getCFdword(DWORD d1, DWORD d2, BOOL cf);

extern BOOL getCFbyte_sbb(BYTE b1, BYTE b2, BOOL cf);
extern BOOL getCFword_sbb(WORD w1, WORD w2, BOOL cf);
extern BOOL getCFdword_sbb(DWORD d1, DWORD d2, BOOL cf);


typedef void (*pEncryptFuncAddr)(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
typedef void (*pDecryptFuncAddr)(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
typedef void (*pUpdateKeyFuncAddr)(WORD* key, WORD dw_key_sig, WORD times);


typedef struct BLOCKDESCRIPTOR
{
    WORD before_bytes;
    WORD before_offset;
    WORD after_offset;
    WORD after_bytes;
}*PBLOCKDESCRIPTOR;


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
	WORD dw_key_sig;
    BYTE bjmpback;
    const char* jmpbackins;

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

//virutkind 1 2 3 4 5 6 7 25
extern void updatekey_1(WORD* key, WORD dw_key_sig, WORD times);

//virutkind 8 16 19
extern void updatekey_2(WORD* key, WORD dw_key_sig, WORD times);

//virutkind a
extern void updatekey_3(WORD* key, WORD dw_key_sig, WORD times);

//virutkind b c e f 12 13 14 15 1a
extern void updatekey_4(WORD* key, WORD dw_key_sig, WORD times);

//virutkind d 11 23 24 26
extern void updatekey_5(WORD* key, WORD dw_key_sig, WORD times);

//virutkind 17
extern void updatekey_6(WORD* key, WORD dw_key_sig, WORD times);

//virutkind 18
extern void updatekey_7(WORD* key, WORD dw_key_sig, WORD times);


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

//virutkind b c e f 12 13 14 15 1a
extern void encrypt_7(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_7(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind d 11
extern void encrypt_8(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_8(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 10 16 19
extern void encrypt_9(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_9(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 17
extern void encrypt_a(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_a(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 18
extern void encrypt_b(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_b(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 23 24 26
extern void encrypt_c(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_c(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 25
extern void encrypt_d(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_d(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);



extern int last_before_off_index;
extern int last_before_off;
extern int last_before_sig;
extern int last_crack_method;
extern int num_off;
extern int num_sig;
extern const BYTE before_sig[0x10][0x20];
extern int before_len[0x10];
extern int before_off_array[0x10];
