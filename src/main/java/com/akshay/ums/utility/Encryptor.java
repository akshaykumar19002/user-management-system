package com.akshay.ums.utility;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 * @author Akshay
 * This class is to encrypt and decrypt strings using DSA algorithm.
 */
public class Encryptor {
	
	private static KeyPairGenerator generator = null;
	private static KeyPair pair = null;
	
	static {
		try {
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			pair = generator.generateKeyPair();
		} catch (Exception e) {
			System.out.println("error: " + e);
		}
	}
	
	public static byte[] encrypt(String plainText) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		PublicKey publicKey = pair.getPublic();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		cipher.update(plainText.getBytes());
		return cipher.doFinal();
	}

	public static String decrypt(byte[] cipherText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
		return new String(cipher.doFinal(cipherText));
	}
}
