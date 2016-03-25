package com.redhat.devops.security.pki.digest;

import java.io.File;
import java.io.FileInputStream;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * 
 * @author ltian
 */
public class FileMD5Utils {

	public static boolean checkFile(String path, String md5) throws Exception{
		
		try(FileInputStream in = new FileInputStream(new File(path));){
			String md5Hex = DigestUtils.md5Hex(in);
			return md5Hex.equals(md5) ? true : false;
		}
	}
}
