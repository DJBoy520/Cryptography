import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

public class SM4 {
    private int[] key;
    private byte[] IV;
    private int fillModel;

    /* 初始化轮密钥 */

    SM4() {
    }

    SM4(byte[] key) {
        this.key = keyGenerate(key);
    }

    public void setKey(byte[] key) {
        this.key = keyGenerate(key);
    }

    public void setIV(byte[] IV) {
        this.IV = IV;
    }

    public void setFillModel(int fillModel) {
        this.fillModel = fillModel;
    }

    /* 密钥拓展 */
    private static int[] keyGenerate(byte[] key_t) {
        int[] key_r = new int[32];
        final int[] FK = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
        final int[] CK = {
                0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
                0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
                0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
                0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
                0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
                0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
                0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
                0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        };
        int[] key_circle = new int[4];
        for (int i = 0; i < 4; i++) {
            key_circle[i] = byteArrayToInt(key_t[i * 4], key_t[i * 4 + 1], key_t[i * 4 + 2], key_t[i * 4 + 3]);
            key_circle[i] = key_circle[i] ^ FK[i];
        }

        int sbox_input, sbox_output;
        for (int i = 0; i < 32; i++) {
            sbox_input = key_circle[1] ^ key_circle[2] ^ key_circle[3] ^ CK[i];
            sbox_output = sBox(sbox_input);
            key_r[i] = sbox_output ^ shiftLeft(sbox_output, 13) ^ shiftLeft(sbox_output, 23) ^ key_circle[0];
            key_circle[0] = key_circle[1];
            key_circle[1] = key_circle[2];
            key_circle[2] = key_circle[3];
            key_circle[3] = key_r[i];
        }
        return key_r;
    }

    /* 加解密主模块 */
    private static byte[] sm4Main(byte[] input, int[] key_r, int mod) {
        int[] input_int = new int[4];
        for (int i = 0; i < 4; i++) {
            input_int[i] = byteArrayToInt(input[i * 4], input[i * 4 + 1], input[i * 4 + 2], input[i * 4 + 3]);
        }
        int sbox_input, sbox_output;
        for (int i = 0; i < 32; i++) {
            int index = (mod == 0) ? i : 31 - i;
            sbox_input = input_int[1] ^ input_int[2] ^ input_int[3] ^ key_r[index];
            sbox_output = sBox(sbox_input);
            int temp = input_int[0] ^ sbox_output ^ shiftLeft(sbox_output, 2) ^ shiftLeft(sbox_output, 10) ^ shiftLeft(sbox_output, 18) ^ shiftLeft(sbox_output, 24);
            input_int[0] = input_int[1];
            input_int[1] = input_int[2];
            input_int[2] = input_int[3];
            input_int[3] = temp;
        }
        byte[] output = new byte[16];
        for (int i = 0; i < 4; i++) {
            byte[] temp = intToByteArray(input_int[3 - i]);
            for (int j = 0; j < 4; j++) {
                output[i * 4 + j] = temp[j];
            }
        }
        return output;
    }

    /* 加密 */
    public byte[] encrypt(byte[] plaintext) {
        return sm4Main(plaintext, this.key, 0);
    }

    public byte[] SM4_ECB_Encrypt(byte[] plaintext) {
        int len_padding = 16 - plaintext.length % 16;
        byte[] ciphertext = new byte[plaintext.length + len_padding];

        int index = 0;
        byte[] temp, temp1, temp2;
        for (index = 0; index < (plaintext.length >>> 4); index++) {
            temp = subByteArray(plaintext, index * 16, 16);
            temp1 = sm4Main(temp, this.key, 0);
            for (int j = 0; j < 16; j++) {
                ciphertext[index * 16 + j] = temp1[j];
            }
        }

        temp = subByteArray(plaintext, index * 16, 16 - len_padding);
        temp1 = PKCS7(temp);
        temp2 = sm4Main(temp1, this.key, 0);
        for (int j = 0; j < 16; j++) {
            ciphertext[index * 16 + j] = temp2[j];
        }
        return ciphertext;
    }

    public byte[] SM4_ECB_Decrypt(byte[] ciphertext) {
        byte[] plaintext = new byte[ciphertext.length];
        byte[] temp, temp1;
        for (int i = 0; i < (ciphertext.length >>> 4); i++) {
            temp = subByteArray(ciphertext, i * 16, 16);
            temp1 = sm4Main(temp, this.key, 1);                         //解密模式
            for (int j = 0; j < 16; j++) {
                plaintext[i * 16 + j] = temp1[j];
            }
        }
        int padding_len = plaintext[plaintext.length - 1];
        return subByteArray(plaintext, 0, plaintext.length - padding_len);
    }

    public byte[] SM4_CBC_Encrypt(byte[] plaintext) {
        int len_padding = 16 - plaintext.length % 16;
        byte[] ciphertext = new byte[plaintext.length + len_padding];

        int index = 0;
        byte[] temp, temp1, temp2;
        byte[] IV = new byte[16];
        System.arraycopy(this.IV, 0, IV, 0, 16);
        for (index = 0; index < (plaintext.length >>> 4); index++) {
            temp = subByteArray(plaintext, index * 16, 16);
            for (int j = 0; j < 16; j++) {
                temp[j] = (byte) (temp[j] ^ IV[j]);
            }
            temp1 = sm4Main(temp, this.key, 0);
            for (int j = 0; j < 16; j++) {
                ciphertext[index * 16 + j] = temp1[j];
                IV[j] = temp1[j];
            }
        }
        temp = subByteArray(plaintext, index * 16, 16 - len_padding);
        temp1 = PKCS7(temp);
        for (int j = 0; j < 16; j++) {
            temp1[j] = (byte) (temp1[j] ^ IV[j]);
        }
        temp2 = sm4Main(temp1, this.key, 0);
        for (int j = 0; j < 16; j++) {
            ciphertext[index * 16 + j] = temp2[j];
        }
        return ciphertext;
    }

    public byte[] SM4_CBC_Decrypt(byte[] ciphertext) {
        byte[] plaintext = new byte[ciphertext.length];
        byte[] temp, temp1;
        byte[] IV = new byte[16];
        System.arraycopy(this.IV, 0, IV, 0, 16);
        for (int i = 0; i < (ciphertext.length >>> 4); i++) {
            temp = subByteArray(ciphertext, i * 16, 16);
            temp1 = sm4Main(temp, this.key, 1);                         //解密模式
            for (int j = 0; j < 16; j++) {
                temp1[j] = (byte) (temp1[j] ^ IV[j]);
                plaintext[i * 16 + j] = temp1[j];
                IV[j] = temp[j];
            }
        }
        int padding_len = plaintext[plaintext.length - 1];
        return subByteArray(plaintext, 0, plaintext.length - padding_len);
    }

    //使用PKCS7填充算法
    private byte[] PKCS7(byte[] src) {
        int index = 0;
        byte[] output = new byte[16];
        for (index = 0; index < src.length; index++) {
            output[index] = src[index];
        }
        for (; index < 16; index++) {
            output[index] = (byte) (16 - src.length);
        }
        return output;
    }

    //截取src数组部分，off为起始位置，length为截取长度，返回一个新的截取后的数组
    private byte[] subByteArray(byte[] src, int off, int length) {
        if ((off + length) > src.length) {
            return null;
        }
        byte[] output = new byte[length];
        for (int i = 0; i < length; i++) {
            output[i] = src[off + i];
        }
        return output;
    }

    /* 解密 */
    public byte[] decrypt(byte[] ciphertext) {
        return sm4Main(ciphertext, this.key, 1);
    }

    /* S盒变换 */
    private static int sBox(int box_input) {
        //s盒的参数
        final int[][] SBOX = {
                {0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05},
                {0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
                {0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62},
                {0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6},
                {0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8},
                {0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35},
                {0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87},
                {0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E},
                {0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1},
                {0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3},
                {0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F},
                {0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51},
                {0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8},
                {0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0},
                {0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84},
                {0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48}
        };
        byte[] temp = intToByteArray(box_input);

        for (int i = 0; i < 4; i++) {
            temp[i] = (byte) SBOX[(temp[i] >> 4) & 0x0f][(temp[i]) & 0x0f];
        }
        return byteArrayToInt(temp[0], temp[1], temp[2], temp[3]);

    }

    /* 将4个8比特数合并成32比特数 */
    private static int byteArrayToInt(byte byte0, byte byte1, byte byte2, byte byte3) {
        return ((byte0 & 0xff) << 24) | ((byte1 & 0xff) << 16) | ((byte2 & 0xff) << 8) | (byte3 & 0xff);
    }

    /* 将32比特数拆分成4个8比特数 */
    private static byte[] intToByteArray(int a) {
        return new byte[]{(byte) ((a >> 24) & 0xff), (byte) ((a >> 16) & 0xff), (byte) ((a >> 8) & 0xff), (byte) ((a) & 0xff)};
    }

    /* 将input左移n位 */
    private static int shiftLeft(int input, int n) {
        return (input >>> (32 - n)) | (input << n);
    }
}

