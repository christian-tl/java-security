package com.redhat.devops.security.pki.asymmetric;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.junit.*;

/**
 * RSA是典型的非对称加密算法。1978年美国麻省理工学院（MIT）的Rom Rivest,Adi Shamir ,and Leonard Adleman三为学者提出。名字由这三位开发者的名字首字母组成。
 * RSA算法是唯一被广泛接受并实现的通用公开的加密算法，目前已经成为非对称加密算法的国际标准。
 * RSA的密钥长度512-65536,默认1024位。
 * RSA算法基于大数因子分解难题，而ElGamal和ECC 算法则基于离散对数难题
 * RSA的加密可以表示为 "求明文的E次方的mod N" ， 解密可以表示为 "求密文的D次方的mod N"
 * 公钥={E,N},E和N的组合就是公钥
 * 私钥={D,N},D和N的组合就是私钥
 * 一旦发现了对大整数进行质因数分解的高效算法，RSA就能够被破解。
 * RSA为代表的公钥密码体系可以解决密钥分发问题，不能防止"中间人攻击"
 * 
 * @author ltian
 *
 */
public class RSA {

	public static final String STR = "测试非对称密码算法RSA";
	byte[] publicKey = null;
	byte[] privateKey = null;
	
	@Before
	public void initKey() throws Exception{
		RSACoder.initKeyPair();
		publicKey = RSACoder.keyMap.get("PUBLIC-KEY");
		privateKey = RSACoder.keyMap.get("PRIVATE-KEY");
		System.out.println("public key is : "+Base64.encodeBase64String(publicKey));
		System.out.println("private key is : "+Base64.encodeBase64String(privateKey));
	}
	
	@Test
	public void test() throws Exception{
		byte[] encodeByPublicKey = RSACoder.encryptByPublicKey(STR.getBytes(), publicKey);
		byte[] decodeByPrivateKey = RSACoder.decryptByPrivateKey(encodeByPublicKey, privateKey);
		System.out.println("明文 :"+STR);
		System.out.println("公钥加密 :"+Base64.encodeBase64String(encodeByPublicKey));
		System.out.println("私钥解密 :"+new String(decodeByPrivateKey));
		
		System.out.println("************************");
		
		byte[] encodeByPrivateKey = RSACoder.encryptByPrivateKey(STR.getBytes(), privateKey);
		byte[] decodeByPublicKey = RSACoder.decryptByPublicKey(encodeByPrivateKey, publicKey);
		System.out.println("明文 :"+STR);
		System.out.println("私钥加密 :"+Base64.encodeBase64String(encodeByPrivateKey));
		System.out.println("公钥解密 :"+new String(decodeByPublicKey));
	}
}

class RSACoder{
    
	private static final String KEY_ALGORITHM = "RSA";
	
	private static final String CIPHER_ALGORITHM = "RSA";
	
	private static final int KEY_SIZE = 1024;
	
	protected static final Map<String,byte[]> keyMap = new HashMap<>();
	
	public static void initKeyPair() throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGenerator.initialize(KEY_SIZE);
		
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		
		keyMap.put("PUBLIC-KEY", publicKey.getEncoded());
		keyMap.put("PRIVATE-KEY", privateKey.getEncoded());
	}
	
	public static byte[] encryptByPublicKey(byte[] data , byte[] secretKey) throws Exception{
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(secretKey);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}
	
	public static byte[] decryptByPublicKey(byte[] data , byte[] secretKey) throws Exception{
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(secretKey);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}
	
	public static byte[] encryptByPrivateKey(byte[] data , byte[] secretKey) throws Exception{
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(secretKey);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey publicKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}
	
	public static byte[] decryptByPrivateKey(byte[] data , byte[] secretKey) throws Exception{
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(secretKey);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey publicKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}
}
