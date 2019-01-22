#pragma once

#include <windows.h>

#define MAXKIND 43       //当前处理的变种数量

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
	BYTE nume8call;       //生效的路径段, 每个virut变种只会有一个同nume8call的waypoint         从0开始
	BYTE bGenBackValue1;  //是否为产生backvalue1的值的那条call指令     这个判断在pLastCode+i为0xe8时用
	BYTE bFollowIn;       //是否跟进e8call,                           这个判断在pLastCode+i为0xe8时用
	BYTE times;      //当遇到指定指令多少次时才跳                    //从1开始, 例如, 碰到jz 一次
	const CHAR *sig[2];  //存放碰到指定次数就跳转的指令
	BYTE off_jmpvalue[2]; //对应跳转指令跳转距离值  距离指令开始的偏移
	BYTE size_jmpvalue[2];//对应跳转指令跳转距离值的字节大小

	BYTE num_confirmed_sig;        //多少个验证标记
	const char *confirmed_sig[0x5]; //存放验证标记
	BYTE confirmed_sig_index[0x5]; //每个验证标记对应的index
};
typedef struct sig_struct
{
	WORD recover_off;
	WORD backvalue_off;
	WORD dw_key_sig;
    BYTE bjmpback;
    const char* jmpbackins;

	BYTE num_waypoint;  //该病毒尾节代码多少个路径点
	waypoint mypath[0x20];                          //数组的元素, nume8call从小到大且唯一
	BYTE lastnume8call;
	BYTE bHasInstructionBeforeJmpBody;
	const char *LastInstructionBeforeJmpBody;
	BYTE LastInstructionSize;

	pEncryptFuncAddr EncryptFunc; //加密过程的函数
	pDecryptFuncAddr DecryptFunc; //解密过程的函数
	pUpdateKeyFuncAddr UpdateKey; //将key用加密算法迭代指定次数, 获得指定位置时的key

}*psig_struct;

extern sig_struct FuckedVirut[MAXKIND + 1];

//有些加解密其实是一样的函数, 但我还是写了两份

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


//virutkind 1 的加解密相关函数
extern void encrypt_1(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_1(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 2 4 5 6 7 的加解密相关函数
extern void encrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_2(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);


//virutkind 3 的加解密相关函数
extern void encrypt_3(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);
extern void decrypt_3(BYTE *data, WORD key, WORD dw_key_sig, WORD decryptsize);

//virutkind 8 的加解密相关函数
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
