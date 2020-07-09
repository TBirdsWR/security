package ppc.security_api.cert;

import ppc.security_api.cert.entity.CertBean;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class AnalysisCert {

    private final static String PKCS12 = "PKCS12";

    public static Certificate getCertFromAnalysisPfx(String pkPath,String pwd) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        //获取p12证书的私钥、公钥证书
        KeyStore ks = KeyStore.getInstance(PKCS12);
        ks.load(new FileInputStream(pkPath), pwd.toCharArray());
        String alias = ks.aliases().nextElement();
        //公钥
        Certificate[] chain = ks.getCertificateChain(alias);
        return chain[0];
    }


    public static PrivateKey getPrivateKeyFromAnalysisPfx(String pkPath,String pwd ) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance(PKCS12);
        ks.load(new FileInputStream(pkPath), pwd.toCharArray());
        String alias = ks.aliases().nextElement();
        //私钥
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pwd.toCharArray());
        return pk;
    }

    public static CertBean getCertAndPrivateKeyFromAnalysisPfx(String pkPath, String pwd) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        //获取p12证书的私钥、公钥证书
        KeyStore ks = KeyStore.getInstance(PKCS12);
        ks.load(new FileInputStream(pkPath), pwd.toCharArray());
        String alias = ks.aliases().nextElement();
        //私钥
        PrivateKey pk = (PrivateKey) ks.getKey(alias, "123456".toCharArray());
        //公钥
        Certificate[] chain = ks.getCertificateChain(alias);
        return new CertBean(chain,pk);
    }

}
