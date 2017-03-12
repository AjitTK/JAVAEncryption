package com.main.DES;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * 
 * @author Ajit
 * 
 *         DES 128 bit ECB No padding example
 *
 */
public class DES128ECBwithNoPadding {

	public static void main(String[] args) {

		// encryption key should be 8 character long
		String key = "12345678";

		String data = "somedata";// input should be multiple of 8

		String encrypted = DES128ECBwithNoPadding.encrypt(data, key);
		System.out.println("encrypted data: " + encrypted);
		String decrypted = DES128ECBwithNoPadding.decrypt(DES128ECBwithNoPadding.encrypt(data, key), key);
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

			SecretKeySpec skey = new SecretKeySpec(key.getBytes(), "DES");

			Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
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
			SecretKeySpec skey = new SecretKeySpec(key.getBytes(), "DES");
			Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, skey);
			output = cipher.doFinal(Base64.decodeBase64(input));
		} catch (Exception e) {
			System.out.println(e.toString());
		}
		return new String(output);
	}

}
