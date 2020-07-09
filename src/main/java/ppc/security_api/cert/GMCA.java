package ppc.security_api.cert;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class GMCA {

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator localKeyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());

        localKeyPairGenerator.initialize(256);

        KeyPair localKeyPair = localKeyPairGenerator.genKeyPair();

        X500NameBuilder localX500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

        localX500NameBuilder.addRDN(BCStyle.CN, "39dian test");

        localX500NameBuilder.addRDN(BCStyle.C, "CN");

        localX500NameBuilder.addRDN(BCStyle.O, "39dian blog");

        localX500NameBuilder.addRDN(BCStyle.L, "shanghai");

        localX500NameBuilder.addRDN(BCStyle.ST, "shanghai");

        localX500NameBuilder.addRDN(BCStyle.EmailAddress, "admin@39dian.com");

        X500Name localX500Name = localX500NameBuilder.build();

        JcaPKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(localX500Name, localKeyPair.getPublic());

        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SM3WITHSM2");// 签名算法

        ContentSigner signer = csBuilder.build(localKeyPair.getPrivate());

//        PKCS10CertificationRequest csr = p10Builder.build(signer);// PKCS10的请求

        PKCS10CertificationRequest csr =  p10Builder.build(signer);

        System.out.println(Base64.encode(csr.getEncoded()));

    }
}
