package ppc.security_api.pdf;

import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import ppc.security_api.cert.AnalysisCert;
import ppc.security_api.cert.entity.CertBean;
import ppc.security_api.pdf.entity.SignatureInfo;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.*;

class PdfSignatureTest {

    public static void main(String[] args) throws Exception {
        PdfSignature.generateBlankSignatureDomain("test.pdf","test1.pdf",350,300,200,100,1,"AREA_SIGNATURE",null);

        //获取p12证书的私钥、公钥证书
        String pkPath = "test.p12";
        CertBean certBean = AnalysisCert.getCertAndPrivateKeyFromAnalysisPfx(pkPath,"123456");

        //封装签章信息
        SignatureInfo info = new SignatureInfo();
        info.setReason("理由");
        info.setLocation("位置");
        info.setPk(certBean.getPrivateKey());
        info.setChain(certBean.getCertificate());
        info.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
        info.setDigestAlgorithm(DigestAlgorithms.SHA1);
        info.setFieldName("AREA_SIGNATURE");
        info.setImagePath("05.png");
        info.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

        PdfSignature.signPdf("test1.pdf", "test2.pdf", info);



    }

}