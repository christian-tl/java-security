package com.redhat.devops.security.pki;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.jce.provider.DHUtil;

public class MainTest {
	
	public static void main(String[] args) throws UnsupportedEncodingException {
		try {
			byte[] data = "123".getBytes("UTF-8");
			MessageDigest md = MessageDigest.getInstance("MD4");
			 md.update(data);
			 byte[] data2 = md.digest();
			 System.out.println("d : " + new String(data2,"UTF-8"));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
				
	}

}
