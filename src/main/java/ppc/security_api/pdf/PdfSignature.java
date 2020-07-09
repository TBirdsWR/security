package ppc.security_api.pdf;

import java.io.*;
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.*;
import ppc.security_api.pdf.entity.SignatureInfo;

public class PdfSignature {

    public static void generateBlankSignatureDomain(String source,String dest,int x, int y,int width, int height,int pageNo,String fieldName,String text) throws IOException, DocumentException {
        PdfReader reader = new PdfReader(source);
        OutputStream os = new FileOutputStream(dest);
        PdfStamper ps = new PdfStamper(reader, os);
        // 创建数组签名域
        // 坐标系远点位于页面左下角，左下角到右下角为  x 轴，左下角到左上角为 y 轴
        Rectangle areaSignatureRect = new Rectangle(// 签名域区域，由两个对角点构成的矩形区域
                x, // 点1 x坐标
                y, // 点1 y坐标
                x + width, // 点2 x坐标
                y + height // 点2 y坐标
        );
        PdfFormField pdfFormField = PdfFormField.createSignature(ps.getWriter());
        pdfFormField.setFieldName(fieldName); // 签名域标识
        pdfFormField.setPage(pageNo);
        pdfFormField.setWidget(areaSignatureRect, PdfAnnotation.HIGHLIGHT_OUTLINE); // 高亮显示
        // 设置区域宽高和边框厚度，以及边框颜色，填充颜色
        PdfAppearance pdfAppearance = PdfAppearance.createAppearance(
                ps.getWriter(),
                width,
                height
        );
        pdfAppearance.setColorStroke(BaseColor.LIGHT_GRAY); // 边框颜色
        pdfAppearance.setColorFill(BaseColor.YELLOW); // 填充颜色
        // 填充矩形区域-开始
        pdfAppearance.rectangle(
                0, // x 轴偏移
                0, // y 轴偏移
                width, // 宽
                height // 高
        );
        pdfAppearance.fillStroke();
        // 填充矩形区域-结束

        // 添加文字-开始
        pdfAppearance.setColorFill(BaseColor.BLACK); // 填充颜色重置为黑色，显示文字
        ColumnText.showTextAligned(
                pdfAppearance,
                Element.ALIGN_CENTER,
                new Phrase(text, new Font()),
                width / 2, // x
                height / 2, // y
                0 // rotation
        );
        // 添加文字-结束

        // 将外观应用到签名域对象之上
        pdfFormField.setAppearance(PdfAnnotation.APPEARANCE_NORMAL, pdfAppearance);

        ps.addAnnotation(pdfFormField, pageNo);

        ps.close();
        os.close();
        reader.close();
    }

    public static void signPdf(String src, String target, SignatureInfo... signatureInfos) {
        InputStream inputStream = null;
        FileOutputStream outputStream = null;
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try {
            inputStream = new FileInputStream(src);
            for (SignatureInfo signatureInfo : signatureInfos) {
                ByteArrayOutputStream tempArrayOutputStream = new ByteArrayOutputStream();
                PdfReader reader = new PdfReader(inputStream);
                //创建签章工具PdfStamper ，最后一个boolean参数是否允许被追加签名
                PdfStamper stamper = PdfStamper.createSignature(reader, tempArrayOutputStream, '\0', null, true);
                // 获取数字签章属性对象
                PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
                appearance.setReason(signatureInfo.getReason());
                appearance.setLocation(signatureInfo.getLocation());
                //设置签名的签名域名称，多次追加签名的时候，签名预名称不能一样，图片大小受表单域大小影响（过小导致压缩）
                appearance.setVisibleSignature(signatureInfo.getFieldName());
                //读取图章图片
                Image image = Image.getInstance(signatureInfo.getImagePath());
                appearance.setSignatureGraphic(image);
                appearance.setCertificationLevel(signatureInfo.getCertificationLevel());
                //设置图章的显示方式，如下选择的是只显示图章（还有其他的模式，可以图章和签名描述一同显示）
                appearance.setRenderingMode(signatureInfo.getRenderingMode());
                // 摘要算法
                ExternalDigest digest = new BouncyCastleDigest();
                // 签名算法
                ExternalSignature signature = new PrivateKeySignature(signatureInfo.getPk(), signatureInfo.getDigestAlgorithm(), null);
                // 调用itext签名方法完成pdf签章
                MakeSignature.signDetached(appearance, digest, signature, signatureInfo.getChain(), null, null, null, 0, signatureInfo.getSubfilter());
                //定义输入流为生成的输出流内容，以完成多次签章的过程
                inputStream = new ByteArrayInputStream(tempArrayOutputStream.toByteArray());
                result = tempArrayOutputStream;
            }
            outputStream = new FileOutputStream(new File(target));
            outputStream.write(result.toByteArray());
            outputStream.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (null != outputStream) {
                    outputStream.close();
                }
                if (null != inputStream) {
                    inputStream.close();
                }
                if (null != result) {
                    result.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
