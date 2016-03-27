package com.redhat.devops.security.pki.certificate;

import static org.junit.Assert.assertTrue;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Before;
import org.junit.Test;

/**
 * DSA与RSA都是数字证书中不可或缺的两种算法。
 * 不同的是DSA只包括数字签名算法，使用DSA算法的数字证书无法进行加密通信，而RSA算法既包含加密/解密算法，同时兼有数字签名算法。
 * 
 * @author ltian
 *
 */
public class DSASignature {
	
	public static final String STR = "测试RSA数字签名";
	byte[] publicKey = null;
	byte[] privateKey = null;
	
	@Before
	public void initKey() throws Exception{
		DSACoder.initKeyPair();
		publicKey = DSACoder.keyMap.get("PUBLIC-KEY");
		privateKey = DSACoder.keyMap.get("PRIVATE-KEY");
		System.out.println("public key is : \n"+Base64.encodeBase64String(publicKey));
		System.out.println("private key is : \n"+Base64.encodeBase64String(privateKey));
	}
	
	@Test
	public void test() throws Exception{
		byte[] sign = DSACoder.sign(STR.getBytes(), privateKey);
		System.out.println("sign : \n"+Hex.encodeHexString(sign));
		
		boolean result = DSACoder.verify(STR.getBytes(), publicKey, sign);
		System.out.println("verify : \n"+result);
		assertTrue(result);
	}
	
}

class DSACoder{
	
	private static final String KEY_ALGORITHM = "DSA";
	
	/**
	 * SHA1EwithDSA
	 * SHA224withDSA
	 * SHA256withDSA
	 * SHA384withDSA
	 * SHA512withDSA
	 */
	private static final String SIGNATURE_ALGORITHM = "SHA1withDSA";
	
	private static final int KEY_SIZE = 1024;
	
	protected static final Map<String,byte[]> keyMap = new HashMap<>();
	
	public static void initKeyPair() throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGenerator.initialize(KEY_SIZE);
		
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		DSAPublicKey publicKey = (DSAPublicKey) keyPair.getPublic();
		DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
		
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
