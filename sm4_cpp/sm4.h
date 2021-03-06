//
// Created by ad on 2022/4/21.
//

#ifndef SM4_CPP_SM4_H
#define SM4_CPP_SM4_H

class SM4 {

private:
    /*系统参数*/
    unsigned long FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

    /*固定参数*/
    unsigned long CK[32] =
            {
                    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
                    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
                    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
                    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
                    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
                    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
                    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
                    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
            };

    /*τ变换S盒*/
    unsigned char SBOX[16][16] =
            {
                    {0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
                    {0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
                    {0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
                    {0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
                    {0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
                    {0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
                    {0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
                    {0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
                    {0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
                    {0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
                    {0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
                    {0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
                    {0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
                    {0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
                    {0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
                    {0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}
            };

    unsigned long rK[32];
    unsigned char key[16];
    unsigned char IV[16];
    unsigned char CTR[16];

    /*!
     *
     * @param char0
     * @param char1
     * @param char2
     * @param char3
     * @return 四个字节从高到低组合起来的unsigned long数据，此处仅赋值低4字节
     */
    unsigned long charToLong(unsigned char char0, unsigned char char1, unsigned char char2, unsigned char char3) {
        unsigned long t = (char0 << 24) | (char1 << 16) | (char2 << 8) | (char3);
        return (char0 << 24) | (char1 << 16) | (char2 << 8) | (char3);
    }

    /*!
     *
     * @param input 待拆解的unsigned long数据，拆解此项的低4字节，unsigned long在不同编译器下字节长度不同，可能有4或8个字节
     * @param b 待返回的拆解后的字节数组的指针
     */
    void LongTochar(unsigned long input, unsigned char *b) {
        b[0] = (input >> 24) & 0xff;
        b[1] = (input >> 16) & 0xff;
        b[2] = (input >> 8) & 0xff;
        b[3] = (input) & 0xff;
    }

    /*!
     *
     * @param input 有待循环左移的unsigned long数据，此函数将input看成4字节进行操作
     * @param n 循环左移的位数
     * @return input循环左移n位后的数据，无符号位
     */
    unsigned long shiftLeft(unsigned long input, int n) {
        return ((input << n) & 0xffffffff) | (input >> (32 - n));
    }

    /*!
     *
     * @param input 输入的unsigned long数据，此处仅操作其低4字节数据
     * @return
     */
    unsigned long sBox(unsigned long input) {
        int i = 0;
        unsigned char temp[4];
        LongTochar(input, temp);
        for (i = 0; i < 4; i++) {
            temp[i] = SBOX[(temp[i] >> 4) & 0x0f][(temp[i]) & 0x0f];
        }
        return charToLong(temp[0], temp[1], temp[2], temp[3]);
    }

    /*!
     *
     * @param key 用户输入的初始化key，可通过构造函数 或 setKey函数设置
     */
    void keyGenerate(unsigned char *key) {
        int i = 0;
        unsigned long key_circle[4];
        unsigned long sbox_input, sbox_output;
        for (i = 0; i < 4; i++) {
            key_circle[i] = charToLong(key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]);
            key_circle[i] = FK[i] ^ key_circle[i];
        }
        for (i = 0; i < 32; i++) {
            sbox_input = key_circle[1] ^ key_circle[2] ^ key_circle[3] ^ CK[i];
            sbox_output = sBox(sbox_input);
            rK[i] = sbox_output ^ shiftLeft(sbox_output, 13) ^ shiftLeft(sbox_output, 23) ^ key_circle[0];
            key_circle[0] = key_circle[1];
            key_circle[1] = key_circle[2];
            key_circle[2] = key_circle[3];
            key_circle[3] = rK[i];
        }
    }

    /*!
     *
     * @param inputText 待操作的数据的指针
     * @param outputText 待返回的数据的指针
     * @param mode sm4操作模式，mode=0加密；mode=1解密
     */
    void sm4Main(unsigned char *inputText, unsigned char *outputText, int mode) {
        int i = 0;
        unsigned long X_circle[4];
        unsigned long sbox_input, sbox_output, temp;
        int index = 0;
        for (i = 0; i < 4; i++) {
            X_circle[i] = charToLong(inputText[i * 4], inputText[i * 4 + 1], inputText[i * 4 + 2],
                                     inputText[i * 4 + 3]);
        }
        for (i = 0; i < 32; i++) {
            if (mode == 0) {
                index = i;
            } else {
                index = 31 - i;
            }
            sbox_input = X_circle[1] ^ X_circle[2] ^ X_circle[3] ^ rK[index];
            sbox_output = sBox(sbox_input);
            temp = sbox_output ^ shiftLeft(sbox_output, 2) ^ shiftLeft(sbox_output, 10) ^ shiftLeft(sbox_output, 18) ^
                   shiftLeft(sbox_output, 24) ^ X_circle[0];
            X_circle[0] = X_circle[1];
            X_circle[1] = X_circle[2];
            X_circle[2] = X_circle[3];
            X_circle[3] = temp;
        }
        for (i = 0; i < 4; i++) {
            LongTochar(X_circle[3 - i], outputText + i * 4);
        }
    }

    /*!
     *
     * @param src 待截取的原字节数组的首指针
     * @param dst 存放截取后的字节数组的首指针
     * @param len 待截取的数据的长度
     */
    void subCharArray(unsigned char *src, unsigned char *dst, unsigned long len) {
        if (dst == nullptr || src == nullptr) {
            return;
        }
        for (int i = 0; i < len; i++) {
            dst[i] = src[i];
        }
    }

    /*!
     *
     * @param src 待填充的原始数据指针
     * @param dst 待返回的 填充过的数据的指针
     * @param len_padding 需要填充的数据的长度
     */
    void PKCS7(unsigned char *src, unsigned char *dst, unsigned long len_padding) {
        unsigned char c = len_padding;
        for (int i = 0; i < 16 - len_padding; i++) {
            dst[i] = src[i];
        }
        for (int i = 16 - len_padding; i < 16; i++) {
            dst[i] = len_padding;
        }
    }

    /*!
     * 根据现有的CTRin，产生CTRout=CTRin+index位置的ctr，这是个相对位置,
     * 此处对unsigned long字节数敏感，所以使用了unsigned long long，在各种编译器上，都是8字节
     * @param CTRin 原始的ctr计数指针
     * @param CTRout 计算过ctr+index后返回的数据的指针
     * @param index 原始的ctr计数指针需要增加的数值
     */
    void generateCTR(unsigned char *CTRin, unsigned char *CTRout, unsigned long long index) {
        unsigned char index_char[8], flag_carry = 0, temp;
        LongTochar(index >> 32, index_char);
        LongTochar(index & 0xffffffff, index_char + 4);
        for (int i = 0; i < 8; i++) {
            temp = 0xff - CTRin[15 - i];
            CTRout[15 - i] = CTRin[15 - i] + index_char[7 - i] + flag_carry;
            flag_carry = (temp < (index_char[7 - i] + flag_carry)) ? 1 : 0;
        }
    }

public:
    SM4();

    /*!
     *
     * @param key 加解密密钥
     */
    SM4(unsigned char *key) {
        for (int i = 0; i < 16; i++) {
            this->key[i] = key[i];
        }
        keyGenerate(this->key);
    };

    /*!
     *
     * @param key 加解密密钥
     * @param IV 初始化向量
     */
    SM4(unsigned char *key, unsigned char *IV) {
        for (int i = 0; i < 16; i++) {
            this->key[i] = key[i];
            this->IV[i] = IV[i];
        }
        keyGenerate(this->key);
    }

    /*!
     *
     * @param key 加解密密钥
     */
    void setKey(unsigned char *key) {
        for (int i = 0; i < 16; i++) {
            this->key[i] = key[i];
        }
        keyGenerate(this->key);
    }

    /*!
     *
     * @param IV 初始化向量
     */
    void setIV(unsigned char *IV) {
        for (int i = 0; i < 16; i++) {
            this->IV[i] = IV[i];
        }
    }

    /*!
     *
     * @param CTR ctr分组加密模式计数器
     */
    void setCTR(unsigned char *CTR) {
        for (int i = 0; i < 16; i++) {
            this->CTR[i] = CTR[i];
        }
    }

    /*!
     *
     * @param plaintext 待加密的数据的指针
     * @param ciphertext 存放待返回的数据的指针
     */
    void encrypt(unsigned char *plaintext, unsigned char *ciphertext) {
        sm4Main(plaintext, ciphertext, 0);
    }

    /*!
     *
     * @param ciphertext 待解密的数据的指针
     * @param plaintext 存放待返回的明文的指针
     */
    void decrypt(unsigned char *ciphertext, unsigned char *plaintext) {
        sm4Main(ciphertext, plaintext, 1);
    }

    /*!
     *
     * @param plaintext 用户输入的明文分组的指针
     * @param ciphertext 待返回的密文分组的指针
     * @param plaintextLen 指定的明文分组长度
     * @param ciphertextLen 待返回的密文分组长度 的指针
     */
    void SM4_ECB_Encrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned long plaintextLen,
                         unsigned long *ciphertextLen) {
        unsigned long len_padding = 16 - plaintextLen % 16;
        *ciphertextLen = 0;
        int index = 0;
        unsigned char temp[16], temp1[16], temp2[16];
        for (index = 0; index < (plaintextLen >> 4); index++) {
            subCharArray(plaintext + index * 16, temp, 16);
            sm4Main(temp, temp1, 0);
            subCharArray(temp1, ciphertext + index * 16, 16);
            *ciphertextLen = (*ciphertextLen) + 16;
        }

        subCharArray(plaintext + index * 16, temp, 16 - len_padding);
        PKCS7(temp, temp1, len_padding);
        sm4Main(temp1, temp2, 0);
        subCharArray(temp2, ciphertext + index * 16, 16);
        *ciphertextLen = (*ciphertextLen) + 16;
    }

    /*!
     *
     * @param ciphertext    用户输入密文分组的指针
     * @param plaintext     待返回的明文分组的指针
     * @param ciphertextLen     指定的密文分组长度
     * @param plaintextLen  待返回的明文分组长度 的指针
     */
    void SM4_ECB_Decrypt(unsigned char *ciphertext, unsigned char *plaintext, unsigned long ciphertextLen,
                         unsigned long *plaintextLen) {
        int index = 0;
        unsigned char temp[16], temp1[16], temp2[16];
        for (index = 0; index < (ciphertextLen >> 4); index++) {
            subCharArray(ciphertext + index * 16, temp, 16);
            sm4Main(temp, temp1, 1);
            subCharArray(temp1, plaintext + index * 16, 16);
        }
        *plaintextLen = ciphertextLen - temp1[15];
    }

    /*!
     *
     * @param plaintext 用户输入的明文分组的指针
     * @param ciphertext 待返回的密文分组的指针
     * @param plaintextLen 指定的明文分组长度
     * @param ciphertextLen 待返回的密文分组长度 的指针
     */
    void SM4_CBC_Encrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned long plaintextLen,
                         unsigned long *ciphertextLen) {
        unsigned long len_padding = 16 - plaintextLen % 16;
        *ciphertextLen = 0;
        int index = 0;
        unsigned char temp[16], temp1[16], temp2[16], IV[16];
        subCharArray(this->IV, IV, 16);
        for (index = 0; index < (plaintextLen >> 4); index++) {
            subCharArray(plaintext + index * 16, temp, 16);
            for (int i = 0; i < 16; i++) {
                temp[i] = temp[i] ^ IV[i];
            }
            sm4Main(temp, temp1, 0);
            for (int i = 0; i < 16; i++) {
                ciphertext[index * 16 + i] = temp1[i];
                IV[i] = temp1[i];
            }
            *ciphertextLen = (*ciphertextLen) + 16;
        }

        subCharArray(plaintext + index * 16, temp, 16 - len_padding);
        PKCS7(temp, temp1, len_padding);
        for (int i = 0; i < 16; i++) {
            temp1[i] = temp1[i] ^ IV[i];
        }
        sm4Main(temp1, temp2, 0);
        subCharArray(temp2, ciphertext + index * 16, 16);
        *ciphertextLen = (*ciphertextLen) + 16;
    }

    /*!
     *
     * @param ciphertext    用户输入密文分组的指针
     * @param plaintext     待返回的明文分组的指针
     * @param ciphertextLen     指定的密文分组长度
     * @param plaintextLen  待返回的明文分组长度 的指针
     */
    void SM4_CBC_Decrypt(unsigned char *ciphertext, unsigned char *plaintext, unsigned long ciphertextLen,
                         unsigned long *plaintextLen) {
        int index = 0;
        unsigned char temp[16], temp1[16], temp2[16], IV[16];
        subCharArray(this->IV, IV, 16);
        for (index = 0; index < (ciphertextLen >> 4); index++) {
            subCharArray(ciphertext + index * 16, temp, 16);
            sm4Main(temp, temp1, 1);
            for (int i = 0; i < 16; i++) {
                temp1[i] = temp1[i] ^ IV[i];
                IV[i] = temp[i];
            }
            subCharArray(temp1, plaintext + index * 16, 16);
        }
        *plaintextLen = ciphertextLen - temp1[15];
    }

    /*!
     *
     * @param plaintext 用户输入的明文分组的指针
     * @param ciphertext 待返回的密文分组的指针
     * @param plaintextLen 指定的明文分组长度
     * @param ciphertextLen 待返回的密文分组长度 的指针
     */
    void SM4_CFB_Encrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned long plaintextLen,
                         unsigned long *ciphertextLen) {
        unsigned long len_padding = 16 - plaintextLen % 16;
        *ciphertextLen = 0;
        int index = 0;
        unsigned char temp[16], temp1[16], temp2[16], IV[16];
        subCharArray(this->IV, IV, 16);
        for (index = 0; index < (plaintextLen >> 4); index++) {
            subCharArray(plaintext + index * 16, temp, 16);
            sm4Main(IV, temp1, 0);
            for (int i = 0; i < 16; i++) {
                temp2[i] = temp[i] ^ temp1[i];
                ciphertext[index * 16 + i] = temp2[i];
                IV[i] = temp2[i];
            }
            *ciphertextLen = (*ciphertextLen) + 16;
        }

        subCharArray(plaintext + index * 16, temp, 16 - len_padding);
        PKCS7(temp, temp1, len_padding);
        sm4Main(IV, temp2, 0);
        for (int i = 0; i < 16; i++) {
            temp2[i] = temp1[i] ^ temp2[i];
            ciphertext[index * 16 + i] = temp2[i];
        }
        *ciphertextLen = (*ciphertextLen) + 16;
    }

    /*!
     *
     * @param ciphertext    用户输入密文分组的指针
     * @param plaintext     待返回的明文分组的指针
     * @param ciphertextLen 指定的密文分组长度
     * @param plaintextLen  待返回的明文分组长度 的指针
     */
    void SM4_CFB_Decrypt(unsigned char *ciphertext, unsigned char *plaintext, unsigned long ciphertextLen,
                         unsigned long *plaintextLen) {
        int index = 0;
        *plaintextLen = 0;
        unsigned char temp[16], temp1[16], IV[16];
        subCharArray(this->IV, IV, 16);
        for (index = 0; index < (ciphertextLen >> 4); index++) {
            subCharArray(ciphertext + index * 16, temp, 16);
            sm4Main(IV, temp1, 0);
            for (int i = 0; i < 16; i++) {
                temp1[i] = temp[i] ^ temp1[i];
                IV[i] = temp[i];
            }
            subCharArray(temp1, plaintext + index * 16, 16);
            *plaintextLen = (*plaintextLen) + 16;
        }
        *plaintextLen = (*plaintextLen) - temp1[15];
    }

    /*!
     *
     * @param plaintext 用户输入的明文分组的指针
     * @param ciphertext 待返回的密文分组的指针
     * @param plaintextLen 指定的明文分组长度
     * @param ciphertextLen 待返回的密文分组长度 的指针
     */
    void SM4_OFB_Encrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned long plaintextLen,
                         unsigned long *ciphertextLen) {
        unsigned long len_padding = 16 - plaintextLen % 16;
        *ciphertextLen = 0;
        int index = 0;
        unsigned char temp[16], temp1[16], temp2[16], IV[16];
        subCharArray(this->IV, IV, 16);
        for (index = 0; index < (plaintextLen >> 4); index++) {
            subCharArray(plaintext + index * 16, temp, 16);
            sm4Main(IV, temp1, 0);
            for (int i = 0; i < 16; i++) {
                temp2[i] = temp[i] ^ temp1[i];
                ciphertext[index * 16 + i] = temp2[i];
                IV[i] = temp1[i];
            }
            *ciphertextLen = (*ciphertextLen) + 16;
        }

        subCharArray(plaintext + index * 16, temp, 16 - len_padding);
        PKCS7(temp, temp1, len_padding);
        sm4Main(IV, temp2, 0);
        for (int i = 0; i < 16; i++) {
            temp2[i] = temp1[i] ^ temp2[i];
            ciphertext[index * 16 + i] = temp2[i];
        }
        *ciphertextLen = (*ciphertextLen) + 16;
    }

    /*!
     *
     * @param ciphertext    用户输入密文分组的指针
     * @param plaintext     待返回的明文分组的指针
     * @param ciphertextLen     指定的密文分组长度
     * @param plaintextLen  待返回的明文分组长度 的指针
     */
    void SM4_OFB_Decrypt(unsigned char *ciphertext, unsigned char *plaintext, unsigned long ciphertextLen,
                         unsigned long *plaintextLen) {
        int index = 0;
        *plaintextLen = 0;
        unsigned char temp[16], temp1[16], temp2[16], IV[16];
        subCharArray(this->IV, IV, 16);
        for (index = 0; index < (ciphertextLen >> 4); index++) {
            subCharArray(ciphertext + index * 16, temp, 16);
            sm4Main(IV, temp1, 0);
            for (int i = 0; i < 16; i++) {
                temp2[i] = temp[i] ^ temp1[i];
                IV[i] = temp1[i];
            }
            subCharArray(temp2, plaintext + index * 16, 16);
            *plaintextLen = (*plaintextLen) + 16;
        }
        *plaintextLen = (*plaintextLen) - temp2[15];
    }

    /*!
     *
     * @param plaintext 用户输入的明文分组的指针
     * @param ciphertext 待返回的密文分组的指针
     * @param plaintextLen 指定的明文分组长度
     * @param ciphertextLen 待返回的密文分组长度 的指针
     */
    void SM4_CTR_Encrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned long plaintextLen,
                         unsigned long *ciphertextLen) {
        unsigned long len_padding = 16 - plaintextLen % 16;
        *ciphertextLen = 0;
        int index = 0;
        unsigned char temp[16], temp1[16], temp2[16], CTR[16];
        subCharArray(this->CTR, CTR, 16);
        for (index = 0; index < (plaintextLen >> 4); index++) {
            subCharArray(plaintext + index * 16, temp, 16);
            sm4Main(CTR, temp1, 0);
            for (int i = 0; i < 16; i++) {
                temp2[i] = temp[i] ^ temp1[i];
                ciphertext[index * 16 + i] = temp2[i];
            }
            generateCTR(CTR, CTR, 1);
            *ciphertextLen = (*ciphertextLen) + 16;
        }

        subCharArray(plaintext + index * 16, temp, 16 - len_padding);
        PKCS7(temp, temp1, len_padding);
        sm4Main(CTR, temp2, 0);
        for (int i = 0; i < 16; i++) {
            temp2[i] = temp1[i] ^ temp2[i];
            ciphertext[index * 16 + i] = temp2[i];
        }
        *ciphertextLen = (*ciphertextLen) + 16;
    }

    /*!
     *
     * @param ciphertext    用户输入密文分组的指针
     * @param plaintext     待返回的明文分组的指针
     * @param ciphertextLen     指定的密文分组长度
     * @param plaintextLen  待返回的明文分组长度 的指针
     */
    void SM4_CTR_Decrypt(unsigned char *ciphertext, unsigned char *plaintext, unsigned long ciphertextLen,
                         unsigned long *plaintextLen) {
        int index = 0;
        *plaintextLen = 0;
        unsigned char temp[16], temp1[16], temp2[16], CTR[16];
        subCharArray(this->CTR, CTR, 16);
        for (index = 0; index < (ciphertextLen >> 4); index++) {
            subCharArray(ciphertext + index * 16, temp, 16);
            sm4Main(CTR, temp1, 0);
            for (int i = 0; i < 16; i++) {
                temp2[i] = temp[i] ^ temp1[i];
            }
            subCharArray(temp2, plaintext + index * 16, 16);
            generateCTR(CTR, CTR, 1);
            *plaintextLen = (*plaintextLen) + 16;
        }
        *plaintextLen = (*plaintextLen) - temp2[15];
    }
};


#endif //SM4_CPP_SM4_H
