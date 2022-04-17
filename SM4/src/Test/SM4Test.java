
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class SM4Test {
    static byte[] data;
    static SM4 sm4_t;
    static int MaxByteNum = 1024 * 1024 * 1024;
    int stepByteNum = 1024 * 1024;
    static long endTime, startTime;

    @BeforeAll
    static void initAll() {
        byte[] key = "1234567812345678".getBytes();//128bit(16byte)
        sm4_t = new SM4(key);
        sm4_t.setIV("1234567812345678".getBytes());

        data = new byte[1024 * 1024 * 1024];
        Random random = new Random();
        System.out.println("init data..........");
        for (int i = 0; i < data.length; i++) {
//            random.nextBytes(data);
        }
        System.out.println("init complete!");
    }


    @org.junit.jupiter.api.BeforeEach
    void setUp() {
    }

    @org.junit.jupiter.api.AfterEach
    void tearDown() {
    }

    @org.junit.jupiter.api.Test
    void SM4_ECB() {
        byte[] plaintext;
        int len;
        System.out.println("start test ECB...........");
        for (int k = 1; k < MaxByteNum / 20; k += stepByteNum * 20) {
            len = k;
            System.out.println("----------------------------------------------------");
            System.out.println("start " + String.valueOf(k) + "st test，data len:" + String.valueOf(len));
            plaintext = new byte[len];
            System.arraycopy(data, 0, plaintext, 0, len);
            startTime = System.currentTimeMillis(); //获取开始时间
            for (int j = 0; j < 1; j++) {
                byte[] g = sm4_t.SM4_ECB_Encrypt(plaintext);
                byte[] h = sm4_t.SM4_ECB_Decrypt(g);
                endTime = System.currentTimeMillis(); //获取开始时间
                for (int i = 0; i < plaintext.length; i++) {
                    assertEquals(plaintext[i], h[i], "SM4_ECB");
                }
            }
            System.out.println("sm4_ECB encrypy and decrypt cost " + (endTime - startTime) + "ms");
            System.out.println("----------------------------------------------------");
        }
    }

    @Order(3)
    @Tag("SM4_CBC")
    @org.junit.jupiter.api.Test
    void SM4_CBC() {
        byte[] plaintext;
        int len;
        System.out.println("start test CBC...........");
        for (int k = 1; k < MaxByteNum / 20; k += stepByteNum * 20) {
            len = k;
            System.out.println("----------------------------------------------------");
            System.out.println("start " + String.valueOf(k) + "st test,data len:" + String.valueOf(len));
            plaintext = new byte[len];
            System.arraycopy(data, 0, plaintext, 0, len);

            startTime = System.currentTimeMillis(); //获取开始时间
            for (int j = 0; j < 1; j++) {
                byte[] g = sm4_t.SM4_CBC_Encrypt(plaintext);
                byte[] h = sm4_t.SM4_CBC_Decrypt(g);
                endTime = System.currentTimeMillis(); //获取开始时间
                for (int i = 0; i < plaintext.length; i++) {
                    assertEquals(plaintext[i], h[i], "SM4_CBC");
                }
            }
            System.out.println("sm4_CBC encrypy and decrypt cost " + (endTime - startTime) + "ms");
            System.out.println("----------------------------------------------------");
        }
    }

    @Order(2)
    @Tag("SM4_CFB")
    @org.junit.jupiter.api.Test
    void SM4_CFB() {
        byte[] plaintext;
        int len;
        System.out.println("start test CFB...........");
        for (int k = 1; k < MaxByteNum / 20; k += stepByteNum * 20) {
            len = k;
            System.out.println("----------------------------------------------------");
            System.out.println("start " + String.valueOf(k) + "st test,data len:" + String.valueOf(len));
            plaintext = new byte[len];
//            System.arraycopy(data, 0, plaintext, 0, len);

            startTime = System.currentTimeMillis(); //获取开始时间
            for (int j = 0; j < 1; j++) {
                byte[] g = sm4_t.SM4_CFB_Encrypt(plaintext);
                byte[] h = sm4_t.SM4_CFB_Decrypt(g);

                endTime = System.currentTimeMillis(); //获取结束时间
                for (int i = 0; i < plaintext.length; i++) {
                    assertEquals(plaintext[i], h[i], "SM4_CFB");
                }
            }
            System.out.println("sm4_CFB encrypy and decrypt cost " + (endTime - startTime) + "ms");
            System.out.println("----------------------------------------------------");
        }
    }

    @Order(1)
    @Tag("SM4_OFB")
    @org.junit.jupiter.api.Test
    void SM4_OFB() {
        int len;
        int index = 1;
        System.out.println("start test OFB...........");
        for (int k = 1; k < MaxByteNum / 20; k += stepByteNum * 200) {
            len = k;
            byte[] plaintext = new byte[len];
            System.out.println("----------------------------------------------------");
            System.out.println("start " + String.valueOf(index++) + "st test,data len:" + String.valueOf(len) + "byte");
//            System.arraycopy(data, 0, plaintext, 0, len);

            startTime = System.currentTimeMillis();   //获取开始时间
            for (int j = 0; j < 1; j++) {
                byte[] g = sm4_t.SM4_OFB_Encrypt(plaintext);
                byte[] h = sm4_t.SM4_OFB_Decrypt(g);

                endTime = System.currentTimeMillis(); //获取结束时间
                for (int i = 0; i < plaintext.length; i++) {
                    assertEquals(plaintext[i], h[i], "SM4_OFB");
                }
            }

            System.out.println("sm4_OFB encrypy and decrypt cost " + (endTime - startTime) + "ms");
            System.out.println("----------------------------------------------------");
        }
    }
}