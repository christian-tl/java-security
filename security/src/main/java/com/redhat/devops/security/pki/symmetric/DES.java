package com.redhat.devops.security.pki.symmetric;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.*;
import org.junit.Test;

/**
 * 称加密算法DES,密钥长度56位。
 * 由于DES的密文可以在短时间内(22h 15min)被破译，因此除了用它解密之前的密文以外，现在不应该再使用DES了。
 * 
 * @author ltian
 *
 */
public class DES {

	public static final String STR = "测试对称加密算法DES";
	
	@Test
	public void test() throws Exception{
		byte[] key = DESCoder.genKey();
		System.out.println("key : "+Base64.encodeBase64String(key));
		
		System.out.println("明文 : "+STR);
		byte[] encrypt_b = DESCoder.encrypt(STR.getBytes(), key);
		System.out.println("密文 : "+Base64.encodeBase64String(encrypt_b));
		
		byte[] decrypt_b = DESCoder.decrypt(encrypt_b, key);
		System.out.println("解密 : "+new String(decrypt_b));
	}
}



class DESCoder{
	
	private static final String KEY_ALGORITHM = "DES";
	
	private static final String CIPHER_ALGORITHM = "DES/ECB/PKCS5Padding";
	
	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static byte[] genKey() throws NoSuchAlgorithmException{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
		keyGenerator.init(56);
		/*keyGenerator.init(new SecureRandom());*/
		SecretKey key = keyGenerator.generateKey();
		return key.getEncoded();
	}
	
	public static Key getKey(byte[] key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		DESKeySpec keySpec = new DESKeySpec(key);
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
