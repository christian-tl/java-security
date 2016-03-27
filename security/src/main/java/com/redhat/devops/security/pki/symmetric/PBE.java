package com.redhat.devops.security.pki.symmetric;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import static org.junit.Assert.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * PBE(Password Based Encryption ,基于口令加密).对称加密算法+消息摘要算法
 * 
 * @author ltian
 *
 */
public class PBE {

	public static final String STR = "测试基于口令加密算法PBE";
	
	@Test
	public void test() throws Exception{
		String password = "tianleisawesome";
		byte[] salt = PBECoder.genSalt();
		System.out.println("salt : "+Base64.encodeBase64String(salt));
		
		System.out.println("明文 : "+STR);
		byte[] encrypt_b = PBECoder.encrypt(STR.getBytes(), salt,password);
		System.out.println("密文 : "+Base64.encodeBase64String(encrypt_b));
		
		byte[] decrypt_b = PBECoder.decrypt(encrypt_b, salt,password);
		System.out.println("解密 : "+new String(decrypt_b));
		
		assertEquals(STR, new String(decrypt_b));
	}
}

class PBECoder{
	
	private static final String ALGORITHM = "PBEWITHMD5andDES";
	
	private static final int ITERA_C = 50;
	
	static{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static byte[] genSalt() throws NoSuchAlgorithmException{
		SecureRandom random = new SecureRandom();
		return random.generateSeed(8);
	}
	
	public static Key getKey(String password) throws Exception {
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
		SecretKey secretKey = keyFactory.generateSecret(keySpec);
		return secretKey;
	}
	
	public static byte[] encrypt(byte[] data, byte[] salt, String password) throws Exception{
		Key key = getKey(password);
		PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, ITERA_C);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key,parameterSpec);
		return cipher.doFinal(data);
	}
	
	public static byte[] decrypt(byte[] data, byte[] salt, String password)throws Exception{
		Key key = getKey(password);
		PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, ITERA_C);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key,parameterSpec);
		return cipher.doFinal(data);
	}
}
