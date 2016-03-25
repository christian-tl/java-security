package com.redhat.devops.security.pki.digest;


import static org.junit.Assert.assertArrayEquals;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

public class MAC {

	public static final String STR = "测试MAC消息认证码API";
	
	@Test
	public void testHmacMD5() throws Exception{
		byte[] key = MCCoder.genKey("HmacMD5");
		byte[] a = MCCoder.encodeHmacMD5(STR.getBytes(),key);
		byte[] b = MCCoder.encodeHmacMD5(STR.getBytes(),key);
		assertArrayEquals(a,b);
		System.out.println("MD5 mac : "+Hex.encodeHexString(b));
	}
	
	@Test
	public void testHmacMD2() throws Exception{
		byte[] b = MCCoder.encodeHmacMD2(STR.getBytes());
		System.out.println("MD2 mac : "+Hex.encodeHexString(b));
	}
	
	@Test
	public void testHmacMD4() throws Exception{
		byte[] b = MCCoder.encodeHmacMD4(STR.getBytes());
		System.out.println("MD4 mac : "+Hex.encodeHexString(b));
	}
	
	@Test
	public void testHmacSHA1() throws Exception{
		byte[] b = MCCoder.encodeHmacSHA1(STR.getBytes());
		System.out.println("SHA1 mac : "+Hex.encodeHexString(b));
	}
	
	@Test
	public void testHmacSHA224() throws Exception{
		byte[] b = MCCoder.encodeHmacSHA224(STR.getBytes());
		System.out.println("SHA224 mac : "+Hex.encodeHexString(b));
	}
	
	@Test
	public void testHmacSHA256() throws Exception{
		byte[] b = MCCoder.encodeHmacSHA256(STR.getBytes());
		System.out.println("SHA256 mac : "+Hex.encodeHexString(b));
	}
	
	@Test
	public void testHmacSHA384() throws Exception{
		byte[] b = MCCoder.encodeHmacSHA384(STR.getBytes());
		System.out.println("SHA384 mac : "+Hex.encodeHexString(b));
	}
	
	@Test
	public void testHmacSHA512() throws Exception{
		byte[] b = MCCoder.encodeHmacSHA512(STR.getBytes());
		System.out.println("SHA512 mac : "+Hex.encodeHexString(b));
	}
}

class MCCoder{
	
	public static byte[] encodeHmacMD5(byte[] data,byte[] key) throws Exception{
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD5");
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);
		return mac.doFinal(data);
	}
	
	public static byte[] encodeHmacMD2(byte[] data) throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD2");
		SecretKey key = keyGen.generateKey();
		
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		return mac.doFinal(data);
	}
	
	public static byte[] encodeHmacMD4(byte[] data) throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD4");
		SecretKey key = keyGen.generateKey();
		
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		return mac.doFinal(data);
	}
	
	public static byte[] encodeHmacSHA1(byte[] data) throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
		SecretKey key = keyGen.generateKey();
		
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		return mac.doFinal(data);
	}
	
	public static byte[] encodeHmacSHA224(byte[] data) throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA224");
		SecretKey key = keyGen.generateKey();
		
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		return mac.doFinal(data);
	}
	
	public static byte[] encodeHmacSHA256(byte[] data) throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
		SecretKey key = keyGen.generateKey();
		
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		return mac.doFinal(data);
	}
	
	public static byte[] encodeHmacSHA384(byte[] data) throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA384");
		SecretKey key = keyGen.generateKey();
		
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		return mac.doFinal(data);
	}
	
	public static byte[] encodeHmacSHA512(byte[] data) throws Exception{
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA512");
		SecretKey key = keyGen.generateKey();
		
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		return mac.doFinal(data);
	}
	
	public static byte[] genKey(String keyType) throws NoSuchAlgorithmException{
		KeyGenerator keyGen = KeyGenerator.getInstance(keyType);
		SecretKey key = keyGen.generateKey();
		return key.getEncoded();
	}
}
