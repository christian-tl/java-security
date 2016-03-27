package com.redhat.devops.security.pki.certificate;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 数字签名算法是公钥基础设施（PKI）以及许多网络安全机制（SSl/TLS,VPN等）的基础。
 * 数字签名算法能够验证数据完整性，认证数据来源，起到不可否认的作用。
 * 
 * @author ltian
 *
 */
public class RSASignature {
	
	public static final String STR = "测试RSA数字签名";
	byte[] publicKey = null;
	byte[] privateKey = null;
	
	@Before
	public void initKey() throws Exception{
		RSACoder.initKeyPair();
		publicKey = RSACoder.keyMap.get("PUBLIC-KEY");
		privateKey = RSACoder.keyMap.get("PRIVATE-KEY");
		System.out.println("public key is : \n"+Base64.encodeBase64String(publicKey));
		System.out.println("private key is : \n"+Base64.encodeBase64String(privateKey));
	}
	
	@Test
	public void test() throws Exception{
		byte[] sign = RSACoder.sign(STR.getBytes(), privateKey);
		System.out.println("sign : \n"+Hex.encodeHexString(sign));
		
		boolean result = RSACoder.verify(STR.getBytes(), publicKey, sign);
		System.out.println("verify : \n"+result);
		assertTrue(result);
	}
	
}

class RSACoder{
	
	private static final String KEY_ALGORITHM = "RSA";
	
	/**
	 * NONEwithRSA
	 * MD2EwithRSA
	 * MD5EwithRSA
	 * SHA1EwithRSA
	 * SHA224withRSA
	 * SHA256EwithRSA
	 * SHA384EwithRSA
	 * SHA512EwithRSA
	 */
	private static final String SIGNATURE_ALGORITHM = "MD5withRSA";
	
	private static final int KEY_SIZE = 1024;
	
	protected static final Map<String,byte[]> keyMap = new HashMap<>();
	
	public static void initKeyPair() throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGenerator.initialize(KEY_SIZE);
		
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		
		keyMap.put("PUBLIC-KEY", publicKey.getEncoded());
		keyMap.put("PRIVATE-KEY", privateKey.getEncoded());
	}
	
	public static byte[] sign(byte[] data , byte[] key) throws Exception{
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}
	
	public static boolean verify(byte[] data , byte[] key, byte[] sign) throws Exception{
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(sign);
	}
	
	
}
