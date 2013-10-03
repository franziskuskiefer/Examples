package de.franziskuskiefer.examples.bc;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class BcExamples {
	
	public static String secretMessage = "This is my very secret message to be encrypted or signed.";

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		
		// AES
		AESExample aes = new AESExample();
		aes.encDecExample(secretMessage);
		
		// RSA
		RSAExample rsa = new RSAExample();
		rsa.signatureExample(secretMessage);
		rsa.encDecExample(secretMessage);
		
		// PGP
		PGPExample pgp = new PGPExample();
		pgp.createKeys();
		pgp.writeKeys();
		pgp.encDec(secretMessage);
	}
	
}
