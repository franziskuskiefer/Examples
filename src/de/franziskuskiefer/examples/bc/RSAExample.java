package de.franziskuskiefer.examples.bc;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAExample {

	// RSA Signature
	public void signatureExample(String message){
		try {

			// KGen
			KeyPairGenerator kGenSign = KeyPairGenerator.getInstance("RSA");
			KeyPair keyPair = kGenSign.generateKeyPair();

			// Sign
			Signature sig = Signature.getInstance("SHA512withRSA");
			sig.initSign(keyPair.getPrivate());
			sig.update(message.getBytes());
			byte[] signature = sig.sign();

			// Verify
			sig = Signature.getInstance("SHA512withRSA");
			sig.initVerify(keyPair.getPublic());
			sig.update(message.getBytes());
			boolean verify = sig.verify(signature);
			System.out.println(verify ? "Good Signature :)" : "Bad Signature :(");

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	}

	// RSA Encryption
	public void encDecExample(String secretMessage) {
		try {
			// KGen
			KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA");
			KeyPair keyPair = kGen.generateKeyPair();

			// Enc
			Cipher enc = Cipher.getInstance("RSA/NONE/OAEPPadding", "BC");
			enc.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
			byte[] cipherText = enc.doFinal(secretMessage.getBytes());

			// Dec
			Cipher dec = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
			dec.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			byte[] message = dec.doFinal(cipherText);
			if (new String(message).equals(secretMessage))
				System.out.println("Successfully decrypted :)");
			else
				System.out.println("Error in decrypting :(");

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} 
	}

}
