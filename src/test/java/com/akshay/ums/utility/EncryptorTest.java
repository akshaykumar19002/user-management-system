package com.akshay.ums.utility;

import org.junit.jupiter.api.Test;

public class EncryptorTest {

	@Test
	public void testEncryption() {
		try {
			byte[] cipher = Encryptor.encrypt("test-text");
			System.out.println("enc-text: " + cipher);
		} catch (Exception e) {
			System.out.println("error1: " + e);
		}
		
	}
	
	@Test
	public void testDecryption() {
		try {
			byte[] cipher = Encryptor.encrypt("test-text");
			System.out.println("enc-text1: " + cipher);
			String plain = Encryptor.decrypt(cipher);
			System.out.println("plain: " + plain);
		} catch (Exception e) {
			System.out.println("error2: " + e);
		}
	}
	
}
