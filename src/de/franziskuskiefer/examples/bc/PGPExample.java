package de.franziskuskiefer.examples.bc;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class PGPExample {

	private PGPKeyRingGenerator rsaKr;
	private PGPKeyRingGenerator dsaKr;
	private char[] pwd = "My$Very@Secure%Password#".toCharArray();
	private int secpar = 2048;
	int pwdCount = 100;

	public void createKeys(){
		String id = "bob@example.com";

		genRsaKeyRing(id, pwd);
		// TODO: DSA, ...
	}

	@SuppressWarnings("unchecked")
	public void encDec(String msg){
		PGPPublicKeyRing publicKeyRing = rsaKr.generatePublicKeyRing();
		Iterator<PGPPublicKey> pks = publicKeyRing.getPublicKeys();
		PGPPublicKey encKey = null;
		int[] preferredSymmetricAlgorithms = null, preferredHashAlgorithms = null;

		// get the first encryption key
		while(pks.hasNext()){
			PGPPublicKey pk = pks.next();
			if (pk.isEncryptionKey()){
				encKey = pk;
				break;
			}
			// get preferred symmetric algorithm
			if (pk.isMasterKey()){
				@SuppressWarnings("rawtypes")
				Iterator v = pk.getSignatures();
				while (v.hasNext()) {
					PGPSignature sig = (PGPSignature)v.next();
					PGPSignatureSubpacketVector hashedSubPackets = sig.getHashedSubPackets();
					preferredSymmetricAlgorithms = getPreferredSymmetricAlgorithms(hashedSubPackets);
					preferredHashAlgorithms = getPreferredHashAlgorithms(hashedSubPackets);
				}
			}
		}

		// encrypt
		int preferredSymAlgo = PGPEncryptedData.AES_256;
		if (preferredSymmetricAlgorithms != null && preferredSymmetricAlgorithms.length != 0)
			preferredSymAlgo = preferredSymmetricAlgorithms[0];
		byte[] ciphertext = encryptText(msg, encKey, preferredSymAlgo);
		
		// decrypt
		String decrypt1 = decrypt(ciphertext, rsaKr.generateSecretKeyRing(), pwd);
		String decrypt2 = decrypt(encodeBase64(ciphertext), rsaKr.generateSecretKeyRing(), pwd);
		if (decrypt1.equals(decrypt2) && decrypt1.equals(msg)){
			System.out.println("Successful PGP enc / dec :)");
		} else {
			System.out.println("Something went wrong in the PGP enc / dec test :(");
		}
	}
	
	public int[] getPreferredSymmetricAlgorithms(PGPSignatureSubpacketVector attributes) {
		SignatureSubpacket p = attributes.getSubpacket(SignatureSubpacketTags.PREFERRED_SYM_ALGS);

		if (p == null) {
			return null;
		}

		return ((PreferredAlgorithms) p).getPreferences();
	}
	
	public int[] getPreferredHashAlgorithms(PGPSignatureSubpacketVector attributes) {
		SignatureSubpacket p = attributes.getSubpacket(SignatureSubpacketTags.PREFERRED_HASH_ALGS);

		if (p == null) {
			return null;
		}

		return ((PreferredAlgorithms) p).getPreferences();
	}
	
	private String decrypt(String in, PGPSecretKeyRing decKeyRing, char[] pass){
		return decrypt(decodeBase64(in), decKeyRing, pass);
	}
	
	private String decrypt(byte[] in, PGPSecretKeyRing decKeyRing, char[] pass){
		try {
			PGPObjectFactory pgpF = new PGPObjectFactory(in);
			PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();
			PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

			BcPBESecretKeyDecryptorBuilder decryptorBuilder = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
			PGPPrivateKey pgpPrivKey = decKeyRing.getSecretKey(encP.getKeyID()).extractPrivateKey(decryptorBuilder.build(pass));

			InputStream text = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivKey));

			return streamToString(text);
		} catch (IOException e){
			e.printStackTrace();
		} catch (PGPException e) {
			e.printStackTrace();
		}

		return null;
	}

	private byte[] encryptText(String sIn, PGPPublicKey encKey, int symAlgo){
		try {
			byte[] sInBytes = sIn.getBytes("UTF-8");
			
			PGPDataEncryptorBuilder encBuilder = new BcPGPDataEncryptorBuilder(symAlgo).setWithIntegrityPacket(true);
			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder);

			encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

			ByteArrayOutputStream baOut = new ByteArrayOutputStream();
			OutputStream cOut = encGen.open(new UncloseableOutputStream(baOut), sInBytes.length);
			cOut.write(sInBytes);
			cOut.close();
			
			return baOut.toByteArray();
		} catch (PGPException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}

	private String streamToString(InputStream in) {
		try {
			int ch;
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			while ((ch = in.read()) >= 0) {
				bOut.write(ch);
			}

			return new String(bOut.toByteArray());
		} catch (IOException e){
			e.printStackTrace();
		}

		return null;
	}
	
	private String encodeBase64(byte[] bytes){
		return new String(Base64.encode(bytes));
	}
	
	private byte[] decodeBase64(String s){
		return Base64.decode(s);
	}

	public void writeKeys(){
		try{
			BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream("pgpPublicKeyRing.pkr"));
			rsaKr.generatePublicKeyRing().encode(out);
			out.close();

			out = new BufferedOutputStream(new FileOutputStream("pgpSecretKeyRing.skr"));
			rsaKr.generateSecretKeyRing().encode(out);
			out.close();
		} catch (IOException e){
			e.printStackTrace();
		}
	}

	private void genRsaKeyRing(String id, char[] pass) {
		try {
			RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();

			// RSA KeyGen parameters
			BigInteger publicExponent = BigInteger.valueOf(0x10001);
			int certainty = 12;
			RSAKeyGenerationParameters rsaKeyGenerationParameters = new RSAKeyGenerationParameters(publicExponent, new SecureRandom(), secpar, certainty);
			kpg.init(rsaKeyGenerationParameters);

			// generate master key (signing) and subkey (enc) 
			Date now = new Date();
			PGPKeyPair kpSign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), now);
			PGPKeyPair kpEnc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), now);

			// sign the master key packet
			PGPSignatureSubpacketGenerator signSigPacket = new PGPSignatureSubpacketGenerator();

			// metadata for master key
			boolean isCritical = true;
			int keyPurpose = KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER;
			signSigPacket.setKeyFlags(isCritical, keyPurpose);

			int[] symAlgos = new int[] {SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.BLOWFISH, SymmetricKeyAlgorithmTags.CAST5};
			signSigPacket.setPreferredSymmetricAlgorithms(isCritical, symAlgos);

			int[] hashAlgos = new int[] {HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256};
			signSigPacket.setPreferredHashAlgorithms(isCritical, hashAlgos);

			signSigPacket.setFeature(isCritical, Features.FEATURE_MODIFICATION_DETECTION);

			// sign encryption subkey
			PGPSignatureSubpacketGenerator signEncPacket = new PGPSignatureSubpacketGenerator();

			// metadata for subkey
			keyPurpose = KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
			signEncPacket.setKeyFlags(isCritical, keyPurpose);


			// digests
			PGPDigestCalculator digest1 = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
			PGPDigestCalculator digest256 = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

			// encryption for secret key
			PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, digest256, pwdCount)).build(pass);

			//  create the keyring
			BcPGPContentSignerBuilder contentSignerBuilder = new BcPGPContentSignerBuilder(kpSign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256);
			rsaKr = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, kpSign, id, digest1, signSigPacket.generate(), null, contentSignerBuilder, pske);

			// encryption subkey
			rsaKr.addSubKey(kpEnc, signEncPacket.generate(), null);
		} catch (PGPException e){
			e.printStackTrace();
		}
	}

}
