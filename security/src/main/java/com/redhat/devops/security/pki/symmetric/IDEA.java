package com.redhat.devops.security.pki.symmetric;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.*;
import org.junit.Test;

/**
 * IDEA(国际数据加密标准),密钥长度128位，到目前为止还没有出现对IDEA的有效攻击。
 * IDEA算法是目前较为常见的电子邮件加密算法之一.
 * 
 * @author ltian
 *
 */
public class IDEA {

	public static final String STR = "测试对称加密算法IDEA";
	
	@Test
	public void test() throws Exception{
		byte[] key = IDEACoder.genKey();
		System.out.println("key : "+Base64.encodeBase64String(key));
		
		System.out.println("明文 : "+STR);
		byte[] encrypt_b = IDEACoder.encrypt(STR.getBytes(), key);
		System.out.println("密文 : "+Base64.encodeBase64String(encrypt_b));
		
		byte[] decrypt_b = IDEACoder.decrypt(encrypt_b, key);
		System.out.println("解密 : "+new String(decrypt_b));
	}
}

class IDEACoder{

	private static final String KEY_ALGORITHM = "IDEA";
	
	private static final String CIPHER_ALGORITHM = "IDEA/ECB/PKCS5Padding";
	
	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static byte[] genKey() throws NoSuchAlgorithmException{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
		keyGenerator.init(128);
		/*keyGenerator.init(new SecureRandom());*/
		SecretKey key = keyGenerator.generateKey();
		return key.getEncoded();
	}
	
	public static Key getKey(byte[] key) {
		SecretKey secretKey = new SecretKeySpec(key,KEY_ALGORITHM);
		return secretKey;
	}
	
	public static byte[] encrypt(byte[] data, byte[] secretKey) throws Exception{
		Key key = getKey(secretKey);
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}
	
	public static byte[] decrypt(byte[] data, byte[] secretKey)throws Exception{
		Key key = getKey(secretKey);
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(data);
	}
}
