package ppc.security_api.security.java;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @ClassName: DemoMain
 * @Description: TODO(国密SM2签名验签/SM3报文摘要)
 * @date 2019年5月10日
 */
public class DemoMain {
	// 国密规范测试用户ID
	private static final String userId = "rzx";
	static String pubk,prik;
	static{
		Map<String,String> map  = SM2Utils.generateSm2KeyPair();
		pubk = map.get("pk");
		prik = map.get("vk");
	}
	public static void main(String[] arg) {

		System.out.println(pubk);
		System.out.println(prik);;
		//createKey();
		String msg = "1234567890123456";//原始数据
		System.out.println("原始数据："+msg);
		String summaryString = summary(msg);
		System.out.println("摘要："+summaryString);
		String signString = sign(summaryString);
		System.out.println("摘要签名："+signString);
		boolean status = verify(summaryString,signString);
		System.out.println("验签结果："+status);

		System.out.println("加密: ");
		byte[] cipherText = null;
		try {
			cipherText = SM2Utils.encrypt132(Util.hexToByte(pubk), msg.getBytes());
		} catch (IllegalArgumentException e1) {
			// TODO 自动生成的 catch 块
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO 自动生成的 catch 块
			e1.printStackTrace();
		}
		System.out.println(Util.byteToHex(cipherText));
		System.out.println("");

		System.out.println("解密: ");
		String res = null;
		try {

			//解密需要添加04标志位
//			res = Util.resolveFillData(Util.byteToHex(SM2Utils.decrypt132(Util.hexToByte("81c99c80fa8a1b84829c6fed058da8b63303b1eceaed3eef83febbd1b0d1632d"),
//					Util.hexToByte("04"+"9ae50b1441592882e69858e8556dc7b0613441dc249a1af57fb2800e367d6a790817913c97790da3045a4bfc62bb2efb1e74250ad10b5fac3e3c19372ee116006086521a98141cb330b4aa3288532a2801f4aa990a9addd707ccc676a9a253684c151c524f6239c34ea199fa00f3a3db563d42e562b9cd8412e08efc20860edf"))),32);
//			res = Util.byteToHex(SM2Utils.decrypt(Util.hexToByte("81c99c80fa8a1b84829c6fed058da8b63303b1eceaed3eef83febbd1b0d1632d"),
//					Util.hexToByte("04d023c4fc4b0d3c1f70f985968887d3ac98df8b7ed987173a3950734b2b8cfc4d876997dd9a76bc7b178e8222e7c6ef7b3c7d69c286139a1796679c66572cd7cb2e3f68260ce2c4ceb8c9f2ed507087464c379091b52a7edb6671727fc93d7ff3c09de91ffbb6cb7ba810a21602416a2495ee723d3f9088eb88794485c8cb94bd".toUpperCase())));
			res = new String(SM2Utils.decrypt132(Util.hexToByte(prik),
					Util.hexToByte("04" + Util.byteToHex(cipherText))));

		} catch (IllegalArgumentException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		} catch (IOException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
		System.out.println(res);

	}

	/**
	 * 摘要
	 * @return
	 */
	public static String summary(String msg) {
		//1.摘要
		byte[] md = new byte[32];
		SM3Digest sm = new SM3Digest();
		sm.update(msg.getBytes(), 0, msg.getBytes().length);
		sm.doFinal(md, 0);
		String s = new String(Hex.encode(md));
		return s.toUpperCase();
	}

	/**
	  * 签名
	 * @return
	 */
	public static String sign(String summaryString) {
		String prikS = new String(Base64.encode(Util.hexToByte(prik)));
		System.out.println("prikS: " + prikS);
		System.out.println("");

		System.out.println("ID: " + Util.getHexString(userId.getBytes()));
		System.out.println("");
		System.out.println("签名: ");
		String sign = null; //摘要签名
		try {
			sign = SM2Utils.sign(userId.getBytes(), Base64.decode(prikS.getBytes()), Util.hexToByte(summaryString));
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return sign;
	}

	/**
	 * 验签
	 * @return
	 */
	public static boolean verify(String summary,String sign) {
		String pubkS = new String(Base64.encode(Util.hexToByte(pubk)));
		System.out.println("pubkS: " + pubkS);
		System.out.println("");

		System.out.println("验签 ");
		boolean vs = false; //验签结果
		try {
			vs = SM2Utils.verifySign(userId.getBytes(), Base64.decode(pubkS.getBytes()), Util.hexToByte(summary), sign);
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return vs;
	}

	/**
	 * 生成随机密钥对
	 */
	public static void createKey() {
		SM2 sm2 = SM2.Instance();
        AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
        BigInteger privateKey = ecpriv.getD();
        ECPoint publicKey = ecpub.getQ();

        System.out.println("公钥: " + Util.byteToHex(publicKey.getEncoded(true)));
        System.out.println("私钥: " + Util.byteToHex(privateKey.toByteArray()));
	}

}
