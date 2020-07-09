package ppc.security_api.certTest;




import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import ppc.security_api.cert.AnalysisCert;
import ppc.security_api.cert.entity.CertBean;
import sun.security.util.KeyUtil;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import org.bouncycastle.asn1.x500.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;
import java.util.Date;

public class X509CertTest {

    public static void main(String[] args) throws Exception {
        String csrFile = "C:\\Users\\Administrator\\Desktop\\test.csr";
        // 创建密钥对
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        // 创建 CSR 对象
        X500Principal subject = new X500Principal("C=CName, ST=STName, L=LName, O=OName, OU=OUName, CN=CNName, EMAILADDRESS=Name@gmail.com");
        ContentSigner signGen = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        // 添加 SAN 扩展
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        GeneralNames generalNames = new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.rfc822Name, "ip=6.6.6.6"), new GeneralName(GeneralName.rfc822Name, "email=666@gmail.com")});
        extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, generalNames);
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        // build csr
        PKCS10CertificationRequest csr = builder.build(signGen);
        // 输出 PEM 格式的 CSR
        OutputStreamWriter output = new OutputStreamWriter(new FileOutputStream(csrFile));
        JcaPEMWriter pem = new JcaPEMWriter(output);
        pem.writeObject(csr);
        pem.close();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // 解析 PEM 格式的 CSR
        FileInputStream fileInputStream = new FileInputStream(csrFile);
        byte[] bs = new byte[fileInputStream.available()];
        fileInputStream.read(bs);
        fileInputStream.close();
        ByteArrayInputStream pemStream = new ByteArrayInputStream(bs);
        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = new PEMParser(pemReader);

        Object parsedObj = pemParser.readObject();
        System.out.println("PemParser returned: " + parsedObj);
        if (parsedObj instanceof PKCS10CertificationRequest) {
            csr = (PKCS10CertificationRequest) parsedObj;
        }

//        SecureRandom secureRandom = new SecureRandom();
//
//        /** 为RSA算法创建一个KeyPairGenerator对象 */
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//
//        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
//        keyPairGenerator.initialize(2048, secureRandom);
//        //keyPairGenerator.initialize(KEYSIZE);
//
//        /** 生成密匙对 */
//        KeyPair rootPair = keyPairGenerator.generateKeyPair();
//
//        // 私钥用来前面
//        PrivateKey issuePriveteKey = rootPair.getPrivate();
//        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//        FileInputStream fileInputStream1 = new FileInputStream("D:\\tomatocc.p12");
//        X509Certificate rootCert = (X509Certificate)certificateFactory.generateCertificate(fileInputStream1);// 利用公钥创建根证书，来签发用户证书

        CertBean certBean = AnalysisCert.getCertAndPrivateKeyFromAnalysisPfx("D:\\tomatocc.p12","123456");
        X509Certificate rootCert = (X509Certificate)certBean.getCertificate()[0];
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
        new X500Name(rootCert.getSubjectDN().getName()),
        BigInteger.valueOf(666666666L),
        new Date(),
        new Date(System.currentTimeMillis() + 1000 * 86400 * 365L),
        csr.getSubject(),
        csr.getSubjectPublicKeyInfo()
        );

        // 读取扩展信息
//        Extensions extensions = null;
//        for (Attribute attr : csr.getAttributes()) {
//            if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
//                extensions = Extensions.getInstance(attr.getAttributeValues()[0]);
//                break;
//            }
//        }
//        if (extensions != null) {
//            // 添加 SAN 扩展
//            certificateBuilder.addExtension(extensions.getExtension(Extension.subjectAlternativeName));
//        }

//        //添加crl扩展
//        GeneralName[] names = new GeneralName[1];
//        names[0] = new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.ca.com/crl");
//        GeneralNames gns = new GeneralNames(names);
//        DistributionPointName pointName = new DistributionPointName(gns);
//        GeneralNames crlIssuer = new GeneralNames(new GeneralName(new X500Name(rootCert.getSubjectDN().getName())));
//        DistributionPoint[] points = new DistributionPoint[1];
//        points[0] = new DistributionPoint(pointName, null, crlIssuer);
//        certificateBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(points));
//
//        //添加aia扩展
//        AccessDescription[] accessDescriptions = new AccessDescription[2];
//        accessDescriptions[0] = new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.ca.com/root.crt"));
//        accessDescriptions[1] = new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.com/"));
//        certificateBuilder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(accessDescriptions));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(Security.getProvider("BC")).build(certBean.getPrivateKey());
        X509CertificateHolder holder = certificateBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(Security.getProvider( "BC")).getCertificate(holder);
        System.out.println(Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded()));
        System.out.println(cert.getNotAfter());
        System.out.println(cert.getNotBefore());
        FileOutputStream fileOutputStream = new FileOutputStream(new File("C:\\Users\\Administrator\\Desktop\\test.cer"));
        fileOutputStream.write(cert.getEncoded());
        fileOutputStream.close();

    }
}
