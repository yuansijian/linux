#include "encrypt_decrypt.h"

//extern char IV[8];
//extern int ccount, c;
//extern char temp[8];
//extern char t[8];


void ECB_encryption(char *data, int low, int len, int key)
{
    char temp = NULL;
    for(int i=low; i<low+len; i++)
    {
        temp = data[i];
        temp = (temp+key)%128;      //Table(ASII) encryption
        data[i] = temp;
    }
}

void ECB_decryption(char *data, int low, int len, int key)
{
    char temp = NULL;
    for(int i=low; i<low+len; i++)
    {
        temp = data[i];
        temp = (char)((temp+128-key)%128);
        data[i] = temp;
    }
}

void CBC_encryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp)
{
    if(a[0] == 1)
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
    ECB_encryption(data, low, len, key);

    //下一个块的异或
    if(a[1] == a[0])
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

void CBC_decryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp)
{
    ECB_decryption(data, low, len, key);

    if(a[0] == 1)
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

    //上一解密模块
    for(int i=low-16, j=0; i<low-8; i++, j++)
    {
        temp[j] = data[i];
    }
}

//CFB加密
void CFB_encryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp)
{
    if(a[0] == 1)
    {
        ECB_encryption(IV, 0, 8, key);
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^IV[j];
        }
    }
    else
    {
        ECB_encryption(temp, 0, 8, key);
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^temp[j];
        }
    }

    //下一个块的异或
    if(a[1] == a[0])
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

//CFB解密
void CFB_decryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp)
{

    if(a[0] == a[1])
    {
        //下一解密模块
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            temp[j] = data[i];
        }

        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^IV[j];
        }
        //ECB_encryption(IV, 0, 8, key);
    }
    else
    {
        char t[8];
        for(int j=0; j<8; j++)
        {
            t[j] = temp[j];
        }
        ECB_encryption(t, 0, 8, key);

        //下一解密模块
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            temp[j] = data[i];
        }

        //ECB_encryption(data, low, len, key);
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^t[j];
        }
    }
}

//PCBC加密
void PCBC_encryption(char *data, int low, int len, int key, int a[2],
                    char *IV, char *temp1, char *temp2)
{
    if(a[0] == 1)
    {
        for(int i=low, j=0; i<low+len; i++, j++)
        {
            temp2[j] = data[i];     //save plaintext
            data[i] = data[i]^IV[j];
        }

        ECB_encryption(data, low, len, key);

        for(int i=low, j=0; i<low+len; i++, j++)
        {
            temp1[j] = data[i];     //save cipher
        }
    }
    else
    {
        char t[8];
        for(int i=0; i<8; i++)
        {
            t[i] = temp1[i]^temp2[i];
        }

        for(int i=low, j=0; i<low+len; i++, j++)
        {
            temp2[j] = data[i];     //save plaintext
            data[i] = data[i]^t[j];
        }

        ECB_encryption(data, low, len, key);

        for(int i=low, j=0; i<low+len; i++, j++)
        {
            temp1[j] = data[i];     //save ciphertext
        }
    }
}
//PCBC解密
void PCBC_decryption(char *data, int low, int len, int key, int a[2],
                    char *IV, char *temp1, char *temp2)
{
    if(a[0] == a[1])
    {
        for(int i=low, j=0; i<len+low; i++, j++)
        {
            temp1[j] = data[i];     //save ciphertext
        }

        ECB_decryption(data, low, len, key);

        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^IV[j];
            temp2[j] = data[i];     //save plaintext
        }
    }
    else
    {
        char t[8];
        for(int i=0; i<8; i++)
        {
            t[i] = temp1[i]^temp2[i];
        }

        for(int i=low, j=0; i<len+low; i++, j++)
        {
            temp1[j] = data[i];     //save ciphertext
        }

        ECB_decryption(data, low, len, key);

        for(int i=low, j=0; i<low+len; i++, j++)
        {
            data[i] = data[i]^t[j];
            temp2[j] = data[i];     //save plaintext
        }
    }
}

//OFB加密
void OFB_encryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp)
{
    if(a[0] == 1)
    {
        ECB_encryption(IV, 0, 8, key);

        for(int i=low, j=0; i<low+len; i++)
        {
            temp[j] = IV[j];
            data[i] = data[i]^IV[j];
        }
    }
    else
    {
        char t[8];

        for(int i=0; i<8; i++)
        {
            t[i] = temp[i];
        }

        ECB_encryption(t, 0, 8, key);

        for(int i=low, j=0; i<low+len; i++)
        {
            temp[j] = t[j];
            data[i] = data[i]^t[j];
        }

    }
}
//OFB解密
void OFB_decryption(char *data, int low, int len, int key, int a[2], char *IV, char *temp)
{
    if(a[0] == a[1])
    {
        ECB_decryption(IV, 0, 8, key);

        for(int i=low, j=0; i<low+len; i++, j++)
        {
            temp[j] = IV[j];
            data[i] = data[i]^IV[j];
        }
    }
    else
    {
        char t[8];

        for(int i=0; i<8; i++)
        {
            t[i] = temp[i];
        }

        ECB_decryption(t, 0, 8, key);

        for(int i=low, j=0; i<low+len; i++, j++)
        {
            temp[j] = t[j];
            data[i] = data[i]^t[j];
        }
    }
}

































