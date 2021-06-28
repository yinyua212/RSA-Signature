package demo;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author YINYUAN
 *
 */
public class RSASSA_PKCS_v1_5_Demo {

	/*
	 * RSASSA_PKCS_v1_5_Demo
	 */
	public static void main(String[] args) {

		try {
			final String message = "Hello Cherri. This is my RSA PKCS_v1-5 signature demo.";
			byte[] messageBytes = message.getBytes();
			
			initialize();
			
			// generate public key & private key
			KeyPair keyPair = generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			
			// sign
			byte[] signature = sign(privateKey, messageBytes);
			
			// verify
			boolean result = verify(publicKey, signature, messageBytes);
			
			//print result
			System.out.println(String.format("ooResult: %s", result));		
	
		}catch(Exception e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * 初始化環境
	 */
	private static void initialize() {
		
		Security.addProvider(new BouncyCastleProvider());
		
	}
	
	/**
	 * 產生公鑰與私鑰
	 * 
	 * @return keyPair
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
		
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyGenerator.initialize(512, new SecureRandom());
		return keyGenerator.generateKeyPair();
		
	}
	
	/**
	 * 產生數位簽章
	 * 
	 * @param privateKey 私鑰
	 * @param message    傳送的訊息(byte[])
	 * @return signature 簽名
	 * 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws SignatureException 
	 */
	private static byte[] sign(PrivateKey privateKey, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException {
		
		Signature privateSig = Signature.getInstance("SHA256withRSA", "BC");
		privateSig.initSign(privateKey);
		privateSig.update(message);
		return  privateSig.sign();
		
	}
	
	/**
	 * 驗證
	 * 
	 * @param publicKey		公鑰
	 * @param signature		簽章
	 * @param message		傳送的訊息(byte[])
	 * @return  true 驗證成功, false 驗證失敗
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 */
	private static boolean verify(PublicKey publicKey, byte[] signature, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		//decrypt signature
		Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byte[] decryptedSignature = cipher.doFinal(signature);
		ASN1InputStream inputStream = new ASN1InputStream(decryptedSignature);
		ASN1Sequence seq = (ASN1Sequence) inputStream.readObject();
		ASN1OctetString hashFromSignature = (ASN1OctetString) seq.getObjectAt(1);
		inputStream.close();

		//digest message
		MessageDigest hashFromMessage = MessageDigest.getInstance("SHA-256", "BC");
		hashFromMessage.update(message);
		
		//Compare hashFromMessage to hashFromSignature		
		return MessageDigest.isEqual(hashFromMessage.digest(), hashFromSignature.getOctets());		
		
	}

}
