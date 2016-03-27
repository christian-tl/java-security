package com.redhat.devops.security.pki.symmetric;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

/**
 * 3重DES，密钥长度56*3=168，目前被一些银行机构使用，但处理速度不高，在安全性方面也逐渐显现出一些问题。
 * 
 * @author ltian
 *
 */
public class DES3 {
	
	public static final String STR = "测试对称加密算法三重DES";
	
	@Test
	public void test() throws Exception{
		byte[] key = DES3Coder.genKey();
		System.out.println("key : "+Base64.encodeBase64String(key));
		
		System.out.println("明文 : "+STR);
		byte[] encrypt_b = DES3Coder.encrypt(STR.getBytes(), key);
		System.out.println("密文 : "+Base64.encodeBase64String(encrypt_b));
		
		byte[] decrypt_b = DES3Coder.decrypt(encrypt_b, key);
		System.out.println("解密 : "+new String(decrypt_b));
	}
}

class DES3Coder{
	
	private static final String KEY_ALGORITHM = "DESede";
	
	private static final String CIPHER_ALGORITHM = "DESede/ECB/PKCS5Padding";
	
	static{
//		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static byte[] genKey() throws NoSuchAlgorithmException{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
		keyGenerator.init(168);
		/*keyGenerator.init(new SecureRandom());*/
		SecretKey key = keyGenerator.generateKey();
		return key.getEncoded();
	}
	
	public static Key getKey(byte[] key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		DESedeKeySpec keySpec = new DESedeKeySpec(key);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
		SecretKey secretKey = keyFactory.generateSecret(keySpec);
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
