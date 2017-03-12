package com.main.AES;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;/**
 * 
 * @author Ajit
 * 
 *         AES 128 bit ECB PKCS7 padding example
 *
 */

public class AES128ECBwithPKCS7 {

	//add new bouncycastle ciphers 
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	public static void main(String[] args) {

		// encryption key should be multiple of 16 character long
		String key = "EncodeStuff00000";
		String data = "some text to encrypt";

		String encrypted = AES128ECBwithPKCS7.encrypt(data, key);
		System.out.println("encrypted data: " + encrypted);
		String decrypted = AES128ECBwithPKCS7.decrypt(AES128ECBwithPKCS7.encrypt(data, key), key);
		System.out.println("decrypted data: " + decrypted);
	}

	/**
	 * encrypt input text
	 * 
	 * @param input
	 * @param key
	 * @return
	 */
	public static String encrypt(String input, String key) {
		byte[] crypted = null;
		try {

			SecretKeySpec skey = new SecretKeySpec(key.getBytes(), "AES");

			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
			cipher.init(Cipher.ENCRYPT_MODE, skey);
			crypted = cipher.doFinal(input.getBytes());
		} catch (Exception e) {
			System.out.println(e.toString());
			e.printStackTrace();
		}

		return new String(Base64.encodeBase64(crypted));
	}

	/**
	 * decrypt input text
	 * 
	 * @param input
	 * @param key
	 * @return
	 */
	public static String decrypt(String input, String key) {
		byte[] output = null;
		try {
			SecretKeySpec skey = new SecretKeySpec(key.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
			cipher.init(Cipher.DECRYPT_MODE, skey);
			output = cipher.doFinal(Base64.decodeBase64(input));
		} catch (Exception e) {
			System.out.println(e.toString());
		}
		return new String(output);
	}

}
