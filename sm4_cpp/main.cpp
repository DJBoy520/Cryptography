#include <iostream>
#include "sm4.h"

int main() {
    unsigned char key[17] = "1234567812345678";
    unsigned char plaintext[64] = "12345678123456781234567812345678";
    unsigned char ciphertext[64] = {0};
    SM4 s = SM4(key);
//    s.encrypt(plaintext, ciphertext);
//    s.decrypt(ciphertext, plaintext);

//    unsigned char temp[17] = "1234567812345678";
//    unsigned char temp1[17] = {0};
//    s.PKCS7(temp+17,temp1,15);
    unsigned long plaintextlen = 17, ciphertextLen;
//    s.SM4_ECB_Encrypt(plaintext, ciphertext, plaintextlen, &ciphertextLen);
//    s.SM4_ECB_Decrypt(ciphertext, plaintext, ciphertextLen, &plaintextlen);
//
//    s.SM4_CBC_Encrypt(plaintext, ciphertext, plaintextlen, &ciphertextLen);
//    s.SM4_CBC_Decrypt(ciphertext, plaintext, ciphertextLen, &plaintextlen);

    s.SM4_CFB_Encrypt(plaintext, ciphertext, plaintextlen, &ciphertextLen);
    for (int i = 0; i < 64; i++) {
        plaintext[i] = 0;
    }
    s.SM4_CFB_Decrypt(ciphertext, plaintext, ciphertextLen, &plaintextlen);

    s.SM4_OFB_Encrypt(plaintext, ciphertext, plaintextlen, &ciphertextLen);
    for (int i = 0; i < 64; i++) {
        plaintext[i] = 0;
    }
    s.SM4_OFB_Decrypt(ciphertext, plaintext, ciphertextLen, &plaintextlen);

    s.SM4_CTR_Encrypt(plaintext, ciphertext, plaintextlen, &ciphertextLen);
    for (int i = 0; i < 64; i++) {
        plaintext[i] = 0;
    }
    s.SM4_CTR_Decrypt(ciphertext, plaintext, ciphertextLen, &plaintextlen);

    unsigned char ctr[16] = {0,0,0,0,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,};
//    s.generateCTR(ctr,ctr,0xffffffffffffffff);

    std::cout << sizeof(unsigned long long) << std::endl;
    return 0;
}
