package com.redhat.devops.security.pki.digest;

import java.security.MessageDigest;

import org.apache.commons.codec.digest.*;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * 
 * MD消息摘要算法家族, MD2,MD4,MD5. 能够产生128比特的散列值(hash值)
 * 2004年被山东大学王小云教授的团队破译.
 * 
 * @author ltian
 *
 */
public class MD {

	public static final String STR = "测试MD消息摘要API";
			
	@Test
	public void testMD2() throws Exception{
		byte[] a = MDCoder.encodeMD2(STR.getBytes());
		byte[] b = MDCoder.encodeMD2(STR.getBytes());
		assertArrayEquals(a,b);
	}
	
	@Test
	public void testMD4() throws Exception{
		byte[] a = MDCoder.encodeMD4(STR.getBytes());
		byte[] b = MDCoder.encodeMD4(STR.getBytes());
		assertArrayEquals(a,b);
	}
	
	@Test
	public void testMD5() throws Exception{
		byte[] a = MDCoder.encodeMD5(STR.getBytes());
		byte[] b = ApacheMDCoder.encodeMD5(STR.getBytes());
		assertArrayEquals(a,b);
	}
	
	@Test
	public void testApacheMD5Hex() throws Exception{
		String a = ApacheMDCoder.encodeMD5Hex(STR);
		String b = ApacheMDCoder.encodeMD5Hex(STR);
		System.out.println("MD5Hex : "+a);
		assertEquals(a,b);
	}
}

/**
 * use jre MessageDigest , BouncyCastle for md4.
 *
 */
class MDCoder{
	
	public static byte[] encodeMD2(byte[] data) throws Exception{
		MessageDigest md = MessageDigest.getInstance("MD2");
		return md.digest(data);
	}
	
	public static byte[] encodeMD5(byte[] data) throws Exception{
		MessageDigest md = MessageDigest.getInstance("MD5");
		return md.digest(data);
	}
	
	public static byte[] encodeMD4(byte[] data) throws Exception{
		//Security.addProvider(new BouncyCastleProvider());
		MessageDigest md = MessageDigest.getInstance("MD4");
		return md.digest(data);
	}
}

/**
 * use Apache commons codec, doesn't support md4.
 *
 */
class ApacheMDCoder{
	
	public static byte[] encodeMD2(byte[] data) throws Exception{
		return DigestUtils.md2(data);
	}
	
	public static byte[] encodeMD5(byte[] data) throws Exception{
		return DigestUtils.md5(data);
	}
	
	public static byte[] encodeMD2(String data) throws Exception{
		return DigestUtils.md2(data);
	}
	
	public static byte[] encodeMD5(String data) throws Exception{
		return DigestUtils.md5(data);
	}
	
	public static String encodeMD2Hex(String data) throws Exception{
		return DigestUtils.md2Hex(data);
	}
	
	public static String encodeMD5Hex(String data) throws Exception{
		return DigestUtils.md5Hex(data);
	}
	
}
