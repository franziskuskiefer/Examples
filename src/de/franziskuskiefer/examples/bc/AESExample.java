package de.franziskuskiefer.examples.bc;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESExample {

	public void encDecExample(String secretMessage){
		// AES Encryption
		try {

			// KGen
			KeyGenerator kGenEnc = KeyGenerator.getInstance("AES");
			SecretKey sk = kGenEnc.generateKey();

			// Encrypt
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, sk);

			byte[] cipherText = cipher.doFinal(secretMessage.getBytes());
			byte[] iv = cipher.getIV();

			// Decrypt
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));
			byte[] decryptedText = cipher.doFinal(cipherText);
			if (new String(decryptedText).equals(secretMessage))
				System.out.println("Successfully decrypted :)");
			else
				System.out.println("Error in decrypting :(");

		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}
	
}
