
public class SM4Testa {
    public static void main(String[] args) {
        byte[] key = "1234567812345678".getBytes();//128bit(16byte)
        byte[] plaintext = "1234567812345678".getBytes();//128bit(16byte)

        SM4 sm4_t = new SM4(key);
        byte[] a = sm4_t.SM4_ECB_Encrypt(plaintext);
        byte[] b = sm4_t.SM4_ECB_Decrypt(a);

        sm4_t.setIV("1234567812345678".getBytes());
        byte[] c = sm4_t.SM4_CBC_Encrypt(plaintext);
        byte[] d = sm4_t.SM4_CBC_Decrypt(c);

        byte[] e = sm4_t.SM4_CFB_Encrypt(plaintext);
        byte[] f = sm4_t.SM4_CFB_Decrypt(e);

        byte[] g = sm4_t.SM4_OFB_Encrypt(plaintext);
        byte[] h = sm4_t.SM4_OFB_Decrypt(g);

        int cc = 1 + 2;
    }
}