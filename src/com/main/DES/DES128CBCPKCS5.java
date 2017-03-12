package com.main.DES;

import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
/**
 * 
 * @author Ajit
 * 
 * AES 128 bit CBC PKCS5 padding example
 *
 */
public class DES128CBCPKCS5 {

	public static void main(String[] args) throws Exception {
		
		// encryption key should be 8 character or multiple of 8 character long
		String key = "12345678";
		String input = "sample test to encrypt";

		String encrypted = encrypt(input, key);

		System.out.println("encrypted data: " + encrypted);

		String decrypted = decrypt(encrypted, key);
		System.out.println("decrypted data: " + decrypted);
	}

	/**
	 * encrypt input text
	 * 
	 * @param plainText
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String plainText, String key) throws Exception {
		byte[] inputByte = plainText.getBytes();

		// Generating IV.
		int ivSize = 8;
		byte[] iv = new byte[ivSize];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		// Hashing key.
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(key.getBytes("UTF-8"));
		byte[] keyBytes = new byte[8];
		System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "DES");

		// Encrypt.
		Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
		byte[] encrypted = cipher.doFinal(inputByte);

		// Combine IV and encrypted part.
		byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
		System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
		System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

		return Base64.encodeBase64String(encryptedIVAndText);
	}

	/**
	 * 
	 * @param encryptedIvText
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(String encryptedIvText, String key) throws Exception {
		int ivSize = 8;
		int keySize = 8;

		byte[] encryptedIvTextBytes = Base64.decodeBase64(encryptedIvText);

		// Extract IV.
		byte[] iv = new byte[ivSize];
		System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

		// Extract encrypted part.
		int encryptedSize = encryptedIvTextBytes.length - ivSize;
		byte[] encryptedBytes = new byte[encryptedSize];
		System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);

		// Hash key.
		byte[] keyBytes = new byte[keySize];
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(key.getBytes());
		System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "DES");

		// Decrypt.
		Cipher cipherDecrypt = Cipher.getInstance("DES/CBC/PKCS5Padding");
		cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
		byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

		return new String(decrypted);
	}

}
