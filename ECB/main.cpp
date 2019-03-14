#include <iostream>
/*
#include <rpc/des_crypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <bitset>
#include <pthread.h>

using namespace std;

char IV[8];
int ccount = 0, c = 0;
char temp[8];
char t[8];
bool flag = false;

/*DES_ECB加密
void ECB_encrypt(const char *key, char *data, int len)
{
    char pkey[8];
    strncpy(pkey, key, 8);
    des_setparity(pkey);
    //len must  be a  multiple  of  8.
    ecb_crypt(pkey, data, len, DES_ENCRYPT);
}
DES_ECB解密
void ECB_decrypt(const char *key, char *data, int len)
{
    char pkey[8];       //带奇偶校验的8字节加密密钥
    strncpy(pkey, key, 8);
    des_setparity(pkey);
    ecb_crypt(pkey, data, len, DES_DECRYPT);
}


DES_CBC加密
void CBC_encrypt(const char *key, char *data, int len, const char *ivec)
{
    char pkey[8];
    strncpy(pkey, key, 8);
    char vec[8];
    strncpy(vec, ivec, 8);
    des_setparity(pkey);
    cbc_crypt(pkey, data, len, DES_ENCRYPT, vec);
}
DES_CBC解密
void CBC_decrypt(const char *key, char *data, int len, const char *ivec)
{
    char pkey[8];
    strncpy(pkey, key, 8);
    char vec[8];
    strncpy(vec, ivec, 8);
    des_setparity(pkey);
    cbc_crypt(pkey, data, len, DES_DECRYPT, vec);
}


void ECB_encrypt(char *data, int low, int len, int key)
{
    char temp = NULL;
    for(int i=low; i<low+len; i++)
    {
        temp = data[i];
        temp = (temp+key)%127;      //Table encryption
        data[i] = temp;
    }
}

void ECB_decrypt(char *data, int low, int len, int key)
{
    char temp = NULL;
    for(int i=low; i<low+len; i++)
    {
        temp = data[i];
        temp = (temp+127-key)%127;
        data[i] = temp;
    }
}

void CBC_encrypt(char *data, int low, int len, int key)
{
    if(ccount == 1)
    {
        //异或运算
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^IV[j];
        }
    }
    else
    {
        //异或运算
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^temp[j];
        }
    }
    ECB_encrypt(data, low, len, key);

    //下一个块的异或
    if(c == ccount)
    {
        return;
    }
    else
    {
        for(int i=low, j=0; i<len+low; i++, j++)
        {
            temp[j] = data[i];
        }
    }
}

void CBC_decrypt(char *data, int low, int len, int key)
{
    ECB_decrypt(data, low, len, key);

    if(ccount == 1)
    {
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^IV[j];
        }
    }
    else
    {
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^temp[j];
        }
    }

    //解密模块
    for(int i=low-16, j=0; i<low; i++, j++)
    {
        temp[j] = data[i];
    }
}
*/
#include "encrypt_decrypt.h"

using namespace std;

int main()
{
    char data[4096] = "abcdefghijklmnop12345678123456788s;'.owqeirpokjofdgjkk.,mnzcnvza";
    int len = strlen(data);
    int mod = 0, key = 4;
    char IV[8];     //初始异或数据
    char temp[8];   //存放下一个明文块与之异或的数据
    char temp1[8];
    char temp2[8];
    int a[2] = {0, 0};
    cout << "plaintext:" << endl;
    for(int i=0; i<len; i++)
    {
        cout << data[i];
    }
    cout << endl;

/*
    ECB_encrypt(data, 0, len, 4);
    for(int i=0; i<len; i++)
    {
        cout << data[i] << ' ';
    }
    cout << endl;

    ECB_decrypt(data, 0, len, 4);
    for(int i=0; i<len; i++)
    {
        cout << data[i] << ' ';
    }
    cout << endl;
*/


    //cout << (char)('a'^'b'^'b');
    for(int i=0; i<8; i++)
    {
        //IV[i] = (char)(rand()%127);
        temp[i] = 'a';
        IV[i] = 'a';
        temp1[i] = 'a';
        temp2[i] = 'a';
    }

    //8个字节一组
    if(len%8 != 0)
    {
        for(int i=0; i<8; i++)
        {
            data[len+i] = 'a';
        }

         mod = (len+8) / 8;
    }
    else
    {
        mod = len / 8;
    }

    a[1] = mod;

    //CBC encrypt
    for(int i=0; i<mod; i++)
    {
        a[0]++;

        CBC_encryption(data, i*8, 8, key, a, IV, temp);
    }
    cout << "CBC encrypt:" << endl;
    for(int i=0; i<len; i++)
    {
        cout << data[i];
    }
    cout << endl;
    //CBC decrypt
    for(int i=mod-1; i>=0; i--)
    {
        CBC_decryption(data, i*8, 8, key, a, IV, temp);
        a[0]--;
    }
    cout << "CBC decrypt:" << endl;
    for(int i=0; i<len; i++)
    {
        cout << data[i];
    }
    cout << endl;


    //CFB encrypt
    for(int i=0; i<mod; i++)
    {
        a[0]++;

        CFB_encryption(data, i*8, 8, key, a, IV, temp);
    }
    cout << "CFB encrypt:" << endl;
    for(int i=0; i<len; i++)
    {
        cout << data[i];
    }
    cout << endl;
    //CFB decrypt
    for(int i=0; i<mod; i++)
    {
        CFB_decryption(data, i*8, 8, key, a, IV, temp);
        a[0]--;
    }
    cout << "CFB decrypt:" << endl;
    for(int i=0; i<len; i++)
    {
        cout << data[i];
    }
    cout << endl;

    //PCBC encrypt
    for(int i=0; i<mod; i++)
    {
        a[0]++;

        PCBC_encryption(data, i*8, 8, key, a, IV, temp1, temp2);
    }
    cout << "PCBC encrypt:" << endl;
    for(int i=0; i<len; i++)
    {
        cout << data[i];
    }
    cout << endl;
    //PCBC decrypt
    for(int i=0; i<mod; i++)
    {
        PCBC_decryption(data, i*8, 8, key, a, IV, temp1, temp2);
        a[0]--;
    }
    cout << "PCBC decrypt:" << endl;
    for(int i=0; i<len; i++)
    {
        cout << data[i];
    }
    cout << endl;

    //OFB encrypt
    for(int i=0; i<mod; i++)
    {
        a[0]++;

        CFB_encryption(data, i*8, 8, key, a, IV, temp);
    }
    cout << "OFB encrypt:" << endl;
    for(int i=0; i<len; i++)
    {
        cout << data[i];
    }
    cout << endl;
    //OFB decrypt
    for(int i=0; i<mod; i++)
    {
        CFB_decryption(data, i*8, 8, key, a, IV, temp);
        a[0]--;
    }
    cout << "OFB decrypt:" << endl;
    for(int i=0; i<len; i++)
    {
        cout << data[i];
    }
    cout << endl;

/*    cout<<len<<endl;
    //获取数据需要多少个8字节容纳
//    int slice_num = 0;
//    if(len % 8 == 0)
//    {
//        slice_num = len/8;
//    }
//    else
//    {
//        slice_num = len/8 + 1;
//    }

//    ECB_encrypt("huayuanl", data, slice_num*8);
//    cout << data << endl;
//    ECB_decrypt("huayuanl", data, slice_num*8);
//    cout << data << endl;

//    CBC_encrypt("huayuanl", data, slice_num*8, "oveabcjj");
//    cout << data << endl;
//    CBC_decrypt("huayuanl", data, slice_num*8, "oveabcjj");
//    cout<<data<<endl;
*/

    return 0;
}
