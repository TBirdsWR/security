package ppc.security_api.cert;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.pkcs10.PKCS10;
import sun.security.x509.*;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;


public class CA {
    public KeyPair kp = null;
    public String password = "";

    private String mKeystore = "D:\\myclientkey.store"; // 密锁库路径

    private char[] mKeystorePass = "654321".toCharArray();// 密锁库密码

    private char[] mSignPrivateKeyPass = "654321".toCharArray();// 取得签发者私锁所需的密码

    private String mSignCertAlias = "client";// 签发者别名

    private String mSignedCert = "D:\\client.csr"; // 被签证书

    private String mNewCert = "D:\\clientSignKey.cer"; // 签发后的新证书全名

    private int mValidityDay = 3000; // 签发后的新证书有效期（天）

    private PrivateKey mSignPrivateKey = null;// 签发者的私锁

    private X509CertInfo mSignCertInfo = null;// 签发证书信息

    private X509CertInfo mSignedCertInfo = null;// 被签证书信息

    public byte[] generateCSR(String alg,int size,String cn) throws NoSuchAlgorithmException, InvalidKeyException, IOException, CertificateException, SignatureException{

        Security.addProvider(new BouncyCastleProvider());
        String strCSR = "";
        String sigAlg = "SHA1WithRSA";
        try {
            if (alg == null || alg.length() <= 0) {
                sigAlg = "SHA1WithRSA";
            } else {
                sigAlg = alg;


                int algSize = 2048;
                if (size != 0) {
                    algSize = size;
                }
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(algSize, new SecureRandom());
                this.kp = kpg.generateKeyPair();


                PublicKey publicKey = this.kp.getPublic();
                PrivateKey privateKey = this.kp.getPrivate();

//                PKCS10 pkcs10 = new PKCS10()

//                sun.security.pkcs.PKCS10 pkcs10 = new sun.security.pkcs.PKCS10(
//                        publicKey);
                PKCS10 pkcs10 = new PKCS10(publicKey);
                Signature signature = Signature.getInstance(sigAlg);
                signature.initSign(privateKey);


                String CN = "defaultUserName";
                if (cn != null && cn.length() > 0) {
                    CN = cn;
                }
                String DN = "CN=" + CN + ",C= CN";


                @SuppressWarnings("restriction")
                sun.security.x509.X500Name x500Name = new sun.security.x509.X500Name(
                        DN);
                pkcs10.encodeAndSign(x500Name, signature);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                PrintStream ps = new PrintStream(baos);
                pkcs10.print(ps);
//                return pkcs10.getEncoded();
//                return baos.toByteArray();
                String strPEMCSR = baos.toString();
                strCSR = strPEMCSR.replaceAll("\r|\n", "");
                strCSR = strCSR.replaceAll(
                        "-----BEGIN NEW CERTIFICATE REQUEST-----", "");
                strCSR = strCSR.replaceAll(
                        "-----END NEW CERTIFICATE REQUEST-----", "");
                System.out.println(strPEMCSR);
                return strPEMCSR.getBytes();
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
// TODO: handle exception
        }
        return null;
    }


    /**

     * 取得签名证书信息

     * @throws Exception

     */

    private void getSignCertInfo() throws Exception

    {

        FileInputStream vFin=null;

        KeyStore vKeyStore=null;

        java.security.cert.Certificate vCert=null;

        X509CertImpl vCertImpl=null;

        byte[] vCertData=null;



        //获取签名证书密锁库

        vFin=new FileInputStream(mKeystore);

        vKeyStore= KeyStore.getInstance("JKS");

        vKeyStore.load(vFin,mKeystorePass);

        //获取签名证书
        Enumeration<String> enumeration = vKeyStore.aliases();
        vCert= vKeyStore.getCertificate(mSignCertAlias);


        vCertData=vCert.getEncoded();

        vCertImpl=new X509CertImpl(vCertData);

        //获取签名证书信息

        mSignCertInfo=(X509CertInfo)vCertImpl.get(X509CertImpl.NAME+"."+X509CertImpl.INFO);

        mSignPrivateKey=(PrivateKey)vKeyStore.getKey(mSignCertAlias,mSignPrivateKeyPass);

        vFin.close();

    }







    /**

     * 取得待签证书信息，并签名待签证书

     *

     * @throws Exception

     */

    private void signCertificate() throws Exception {

        FileInputStream vFin = null;

        java.security.cert.Certificate vCert = null;

        CertificateFactory vCertFactory = null;

        byte[] vCertData = null;

        X509CertImpl vCertImpl = null;



        // 获取待签名证书

        vFin = new FileInputStream(mSignedCert);

//        vCertFactory = CertificateFactory.getInstance("X.509");

//        vCert = vCertFactory.generateCertificate(vFin);

        vFin.close();

//        vCertData = vCert.getEncoded();

        // 设置签名证书信息：有效日期、序列号、签名者、数字签名算发

        vCertImpl = new X509CertImpl(generateCSR("SHA1WithRSA",0,""));

        mSignedCertInfo = (X509CertInfo) vCertImpl.get(X509CertImpl.NAME + "."

                + X509CertImpl.INFO);

        mSignedCertInfo.set(X509CertInfo.VALIDITY, getCertValidity());

        mSignedCertInfo.set(X509CertInfo.SERIAL_NUMBER, getCertSerualNumber());

        mSignedCertInfo.set(X509CertInfo.ISSUER + "."

                        + CertificateIssuerName.DN_NAME,

                mSignCertInfo.get(X509CertInfo.SUBJECT + "."

                        + CertificateIssuerName.DN_NAME));

        mSignedCertInfo.set(CertificateAlgorithmId.NAME + "."

                + CertificateAlgorithmId.ALGORITHM, getAlgorithm());



    }



    /**

     * 待签签证书被签名后，保存新证书

     *

     * @throws Exception

     */

    private void createNewCertificate() throws Exception {

        FileOutputStream vOut = null;

        X509CertImpl vCertImpl = null;

        // 用新证书信息封成为新X.509证书

        vCertImpl = new X509CertImpl(mSignedCertInfo);

        // 生成新正书验证码

        vCertImpl.sign(mSignPrivateKey, "MD5WithRSA");

        vOut = new FileOutputStream(mNewCert );

        // 保存为der编码二进制X.509格式证书

        vCertImpl.derEncode(vOut);

        vOut.close();



    }



    // 辅助方法===========================================================================



    /**

     * 得到新证书有效日期

     *

     * @throws Exception

     * @return CertificateValidity

     */

    private CertificateValidity getCertValidity() throws Exception {

        long vValidity = (60 * 60 * 24 * 1000L) * mValidityDay;

        Calendar vCal = null;

        Date vBeginDate = null, vEndDate = null;

        vCal = Calendar.getInstance();

        vBeginDate = vCal.getTime();

        vEndDate = vCal.getTime();

        vEndDate.setTime(vBeginDate.getTime() + vValidity);

        return new CertificateValidity(vBeginDate, vEndDate);

    }



    /**

     * 得到新证书的序列号

     *

     * @return CertificateSerialNumber

     */

    private CertificateSerialNumber getCertSerualNumber() {

        Calendar vCal = null;

        vCal = Calendar.getInstance();

        int vSerialNum = 0;

        vSerialNum = (int) (vCal.getTimeInMillis() / 1000);

        return new CertificateSerialNumber(vSerialNum);

    }



    /**

     * 得到新证书的签名算法

     *

     * @return AlgorithmId

     */

    private AlgorithmId getAlgorithm() {

        AlgorithmId vAlgorithm = new AlgorithmId(

                AlgorithmId.md5WithRSAEncryption_oid);

        return vAlgorithm;

    }




    public void  Sign() throws Exception{

        try {

            /**

             * 证书签名

             */

            getSignCertInfo(); // 获取签名证书信息

            signCertificate(); // 用签名证书信息签发待签名证书

            createNewCertificate(); // 创建并保存签名后的新证书

        } catch (Exception e) {

            System.out.println("Error:" + e.getMessage());

        }

    }
    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, CertificateException, SignatureException, IOException {
        CA ca = new CA();
        System.out.println(ca.generateCSR("SHA1WithRSA",0,""));


//        try {
//
//            ca.Sign();
//
//        } catch (Exception e) {
//
//            e.printStackTrace();
//
//        }
    }

}
