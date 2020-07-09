package ppc.security_api.security.java;



import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA加、解密算法工具类
 */
public class RSAUtil {

    /**
     * 加密算法AES
     */
    private static final String KEY_ALGORITHM = "RSA";

    /**
     * 算法名称/加密模式/数据填充方式
     * 默认：RSA/ECB/PKCS1Padding
     */
    private static final String ALGORITHMS = "RSA/ECB/PKCS1Padding";

    /**
     * Map获取公钥的key
     */
    private static final String PUBLIC_KEY = "publicKey";

    /**
     * Map获取私钥的key
     */
    private static final String PRIVATE_KEY = "privateKey";

    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /**
     * RSA 位数 如果采用2048 上面最大加密和最大解密则须填写:  245 256
     */
    private static final int INITIALIZE_LENGTH = 1024;

    /**
     * 后端RSA的密钥对(公钥和私钥)Map，由静态代码块赋值
     */
    private static Map<String, Object> genKeyPair = new HashMap<>();

    static {
        try {
            genKeyPair.putAll(genKeyPair());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成密钥对(公钥和私钥)
     */
    private static Map<String, Object> genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(INITIALIZE_LENGTH);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        //公钥
        keyMap.put(PUBLIC_KEY, publicKey);
        //私钥
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }


    private static String format2PemString(String type, byte[] privateKeyPKCS1) throws Exception {
        PemObject pemObject = new PemObject(type, privateKeyPKCS1);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        String pemString = stringWriter.toString();
        return pemString;
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 已加密数据
     * @param privateKey    私钥(BASE64编码)
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {

        String result = null;
        //extract valid key content
            //将BASE64编码的私钥字符串进行解码
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag);    //PKCSObjectIdentifiers.pkcs8ShroudedKeyBag

        ASN1InputStream localASN1InputStream = new ASN1InputStream(keyBytes);
        ASN1Object asn1Object = (ASN1Object)localASN1InputStream.readObject();

            PrivateKeyInfo privKeyInfo = new PrivateKeyInfo(algorithmIdentifier, asn1Object);
            byte[] pkcs8Bytes = privKeyInfo.getEncoded();



        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);

        //设置加密、填充方式
        /*
            如需使用更多加密、填充方式，引入
            <dependency>
                <groupId>org.bouncycastle</groupId>
                <artifactId>bcprov-jdk16</artifactId>
                <version>1.46</version>
            </dependency>
            并改成
            Cipher cipher = Cipher.getInstance(ALGORITHMS ,new BouncyCastleProvider());
         */
        Cipher cipher = Cipher.getInstance(ALGORITHMS);
        cipher.init(Cipher.DECRYPT_MODE, privateK);

        //分段进行解密操作
        return encryptAndDecryptOfSubsection(encryptedData, cipher, MAX_DECRYPT_BLOCK);
    }

    /**
     * 公钥加密
     *
     * @param data      源数据
     * @param publicKey 公钥(BASE64编码)
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
        //base64格式的key字符串转Key对象
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);

        //设置加密、填充方式
        /*
            如需使用更多加密、填充方式，引入
            <dependency>
                <groupId>org.bouncycastle</groupId>
                <artifactId>bcprov-jdk16</artifactId>
                <version>1.46</version>
            </dependency>
            并改成
            Cipher cipher = Cipher.getInstance(ALGORITHMS ,new BouncyCastleProvider());
         */
        Cipher cipher = Cipher.getInstance(ALGORITHMS);
        cipher.init(Cipher.ENCRYPT_MODE, publicK);

        //分段进行加密操作
        return encryptAndDecryptOfSubsection(data, cipher, MAX_ENCRYPT_BLOCK);
    }

    /**
     * 获取私钥
     */
    public static String getPrivateKey() {
        Key key = (Key) genKeyPair.get(PRIVATE_KEY);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * 获取公钥
     */
    public static String getPublicKey() {
        Key key = (Key) genKeyPair.get(PUBLIC_KEY);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * 分段进行加密、解密操作
     */
    private static byte[] encryptAndDecryptOfSubsection(byte[] data, Cipher cipher, int encryptBlock) throws Exception {
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > encryptBlock) {
                cache = cipher.doFinal(data, offSet, encryptBlock);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * encryptBlock;
        }
        byte[] toByteArray = out.toByteArray();
        out.close();
        return toByteArray;
    }

    public static void main(String[] args) throws Exception {
        byte[] s = decryptByPrivateKey(Base64.getDecoder().decode("mbnf4UgTILGP4fE8iOFGB0iHWNUtPj4bNs5rfub8Rb4Ulpd/UN2t1G7KVqYzbL3/XnPkfr9ZA8bJ93+CLqbmQPxR6W+tZTLj+gO/vyoNSuU958Y+ZjBciRHAbqYmtSZYNtJbZYo2CZzjfudLSoW2M9nzJku9dxnQIegGr3krKT8="),
                "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMxPTn4T4Qfst5R4RROuI+GMjzHmvCvUnAfMQky+ukqoaM2qidKNHj/xZLaRaybezKpSP8DuimUvRu7meng7qJuXvfxpNIxy798pwDAPthh1zAf6KCXRVRZSLdeLAiozVmtOFY9JwGxzA3u/q6I053bHq9kmYX/+s1Dz/h83i0o5AgMBAAECgYEAqK7t0oBdMerKY0WtWqNTMpyXeY7UW6fNL08AilaKfqtu5CdiZTln+Uk3atjDTDN1bUY9JvCLySDwgrw971jqShkiagdlWQb1DdLPmurWHEd2CLMfby8Y80UGTcfjIJpuNQWNKLbzPcsh0t5aeFQuceMp14KO91w6jlOo3ehIsxECQQD6Lz9zEjE5HlJR0i4pyCcVtXFZlGfkw9lqcuq+Ix47qTxa17u2k5mOlacuhXfqCl7i3W07hY1PQstxuQMmyIrdAkEA0Q8TXQWJYvrCh2hVaTq166W9QIAMme1PVB1DgzxG+1IGgR1oNtYuxmWxVAerYUCxrGvZRulk+JWKW3ko1ZDhDQJBAL35xL93cANEgBP7euxlPTCh39m69I1lHqJTcudAuYNqRhdhO/wu5mq8Pv/3f5ArodO5emm5Rw2J1fycFcWMgM0CQCyI4p4ZVNgSBSilUDSXfjOR3gwEeyq7Q//uL/if+ZsGMT6GDjJIVDSNa0Y0UAzqpC7P1rxlcc4GxS+RUuKT920CQATE+PVh1UGoooveQqHOZxJHyDdAszAJ1GUn205k/NOHbeHk5LM7H7qPVpPWDF/My4+r3j01LbhE/QUnoVPvZjY=");
        System.out.println(new String(s));
        //字符串

        Map map = genKeyPair();
        RSAPublicKey pk = (RSAPublicKey)map.get(PUBLIC_KEY);
        RSAPrivateKey vk = (RSAPrivateKey)map.get(PRIVATE_KEY);

        System.out.println(Base64.getEncoder().encodeToString(pk.getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(vk.getEncoded()));

        s = encryptByPublicKey("cmf1358狗蛋".getBytes(),Base64.getEncoder().encodeToString(pk.getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(s));
    }
}

