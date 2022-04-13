import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import cn.hutool.core.util.HexUtil;

public class SM4Test {
    public static void main(String[] args) {
        // key必须是16位
        byte[] key = "1234567812345678".getBytes();//128bit(16byte)
        byte[] plaintext = "1234567812345678".getBytes();//128bit(16byte)

//        SymmetricCrypto sm4 = SmUtil.sm4(key);
//        byte[] ciphertext = sm4.encrypt(plaintext);//库加密结果
//        System.out.println("库函数加密结果\t\t" + new String(HexUtil.encodeHex(ciphertext)));
        //e863652f50ad5ed9fcc038b25deb07101db94f833e5b4cf024c8f8d61d70d48c

        SM4 sm4_t = new SM4(key);
        byte[] ciphertext_t = sm4_t.encrypt(plaintext);//自己写的函数加密结果
        System.out.println("自己写的函数加密结果\t" + new String(HexUtil.encodeHex(ciphertext_t)));
        //e863652f50ad5ed9fcc038b25deb0710

        byte[] res = sm4_t.decrypt(ciphertext_t);
        System.out.println("加解密正确性\t\t\t" + new String(res).equals(new String(plaintext)));
        //true

        //byte[] padding = sm4_t.encrypt(HexUtil.decodeHex("10101010101010101010101010101010"));
        //System.out.println("填充位数据加密结果\t\t" + new String(HexUtil.encodeHex(padding)));
        //1db94f833e5b4cf024c8f8d61d70d48c
    }
}