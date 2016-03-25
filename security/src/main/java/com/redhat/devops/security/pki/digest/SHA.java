package com.redhat.devops.security.pki.digest;

import java.security.MessageDigest;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.*;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * 
 * SHA消息摘要算法家族, SHA-1,SHA-256,SHA-384,SHA-512.
 * SHA-1,  能够产生160比特的散列值.
 * SHA-256,能够产生256比特的散列值.
 * SHA-384,能够产生384比特的散列值.
 * SHA-512,能够产生512比特的散列值.
 * SHA-1,2005年被山东大学王小云教授的团队破译.
 * 
 * @author ltian
 *
 */
public class SHA {

	public static final String STR = "测试SHA消息摘要API";
	
	@Test
	public void testSHA1() throws Exception{
		byte[] a = SHACoder.encodeSHA1(STR.getBytes());
		byte[] b = ApacheSHACoder.encodeSHA1(STR);
		assertArrayEquals(a,b);
	}
	
	@Test
	public void testSHA1Hex() throws Exception{
		String a = SHACoder.encodeSHA1Hex(STR.getBytes());
		String b = ApacheSHACoder.encodeSHA1Hex(STR);
		assertEquals(a,b);
		System.out.println("sha1Hex : "+a);
	}
}

/**
 * use jre MessageDigest , BouncyCastle for SHA-224.
 *
 */
class SHACoder{
	
	public static byte[] encodeSHA1(byte[] data) throws Exception{
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		return md.digest(data);
	}
	
	public static byte[] encodeSHA256(byte[] data) throws Exception{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(data);
	}
	
	public static byte[] encodeSHA384(byte[] data) throws Exception{
		MessageDigest md = MessageDigest.getInstance("SHA-384");
		return md.digest(data);
	}
	
	public static byte[] encodeSHA512(byte[] data) throws Exception{
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		return md.digest(data);
	}
	
	public static byte[] encodeSHA224(byte[] data) throws Exception{
		//Security.addProvider(new BouncyCastleProvider());
		MessageDigest md = MessageDigest.getInstance("SHA-224");
		return md.digest(data);
	}
	
	public static String encodeSHA1Hex(byte[] data) throws Exception{
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		return new String(Hex.encodeHexString(md.digest(data)));
	}
	
}

/**
 * use Apache commons codec, doesn't support SHA-224.
 *
 */
class ApacheSHACoder{
	
	public static byte[] encodeSHA1(String data)throws Exception{
		return DigestUtils.sha1(data);
	}
	
	public static byte[] encodeSHA256(String data)throws Exception{
		return DigestUtils.sha256(data);
	}
	
	public static byte[] encodeSHA384(String data)throws Exception{
		return DigestUtils.sha384(data);
	}
	
	public static byte[] encodeSHA512(String data)throws Exception{
		return DigestUtils.sha512(data);
	}
	
	public static String encodeSHA1Hex(String data)throws Exception{
		return DigestUtils.sha1Hex(data);
	}
	
	public static String encodeSHA256Hex(String data)throws Exception{
		return DigestUtils.sha256Hex(data);
	}
	
	public static String encodeSHA384Hex(String data)throws Exception{
		return DigestUtils.sha384Hex(data);
	}
	
	public static String encodeSHA512Hex(String data)throws Exception{
		return DigestUtils.sha512Hex(data);
	}
}
