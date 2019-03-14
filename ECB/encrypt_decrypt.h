#ifndef ENCRYPTDECRYPT_H
#define ENCRYPTDECRYPT_H

#include <rpc/des_crypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <bitset>
#include <pthread.h>


void ECB_encryption(char *data, int low, int len, int key);        //ECB加密
void ECB_decryption(char *data, int low, int len, int key);        //ECB解密
//CBC加密
void CBC_encryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp);
//CBC解密
void CBC_decryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp);
//CFB加密
void CFB_encryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp);
//CFB解密
void CFB_decryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp);
//PCBC加密
void PCBC_encryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp1, char *temp2);
//PCBC解密
void PCBC_decryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp, char *temp2);
//OFB加密
void OFB_encryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp);
//OFB解密
void OFB_decryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp);

#endif // ENCRYPTDECRYPT_H
