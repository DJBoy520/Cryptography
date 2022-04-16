import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import cn.hutool.core.util.HexUtil;

import java.nio.charset.StandardCharsets;

public class SM4Test {
    public static void main(String[] args) {
        byte[] key = "1234567812345678".getBytes();//128bit(16byte)
        byte[] plaintext = "12345678123456781".getBytes();//128bit(16byte)

        SM4 sm4_t = new SM4(key);
        byte[] a = sm4_t.SM4_ECB_Encrypt(plaintext);
        byte[] b = sm4_t.SM4_ECB_Decrypt(a);

        sm4_t.setIV("1234567812345678".getBytes());
        byte[] c = sm4_t.SM4_CBC_Encrypt(plaintext);
        byte[] d = sm4_t.SM4_CBC_Decrypt(c);

        int cc = 1 + 2;
    }
}