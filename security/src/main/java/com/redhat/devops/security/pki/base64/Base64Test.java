package com.redhat.devops.security.pki.base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.junit.Test;

import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;

/**
 * 
 * @author ltian
 */
@SuppressWarnings("restriction")
public class Base64Test {

	public final static String ENCODING = "UTF-8";
	public final static String SOURCE = "红帽成为首个年收入20亿美元公司";
	
	/**
	 * bouncy castle base64 encode/decode string
	 * 
	 */
	@Test
	public void testbouncycastleBase64() throws UnsupportedEncodingException{
		String source = SOURCE;
		System.out.println("source : "+source);
		
		byte[] a = org.bouncycastle.util.encoders.Base64.encode(source.getBytes(ENCODING));
		String encode = new String(a,ENCODING);
		
		System.out.println("encode : " +encode);
		
		byte[] b = org.bouncycastle.util.encoders.Base64.decode(encode.getBytes(ENCODING));
		String decode = new String(b,ENCODING);
		
		System.out.println("decode : " +decode); 
	}
	
	/**
	 * Apache commons codec base64 encode/decode string
	 * 
	 */
	@Test
	public void testcodecBase64() throws UnsupportedEncodingException{
		String source = SOURCE;
		System.out.println("source : "+source);
		
		//byte[] a = org.apache.commons.codec.binary.Base64.encodeBase64(source.getBytes(ENCODING));
		byte[] a = org.apache.commons.codec.binary.Base64.encodeBase64(source.getBytes(ENCODING),true);
		String encode = new String(a, ENCODING);
		
		System.out.println("encode : " +encode);
		
		byte[] b = org.apache.commons.codec.binary.Base64.decodeBase64(encode.getBytes(ENCODING));
		String decode = new String(b, ENCODING);
		
		System.out.println("decode : " +decode);
	}
	
	/**
	 * sun jre default base64 encode/decode string
	 * (not recommend)
	 */
	@Test
	public void testsunBase64() throws IOException{
		String source = SOURCE;
		System.out.println("source : "+source);
		
		BASE64Encoder encoder = new BASE64Encoder();
		byte[] a = source.getBytes(ENCODING);
		String encode = encoder.encodeBuffer(a);
		
		System.out.println("encode : " +encode);
		BASE64Decoder decoder = new BASE64Decoder();
		byte[] b = decoder.decodeBuffer(encode);
		String decode = new String(b,ENCODING);
		
		System.out.println("decode : " +decode); 
	}
}
