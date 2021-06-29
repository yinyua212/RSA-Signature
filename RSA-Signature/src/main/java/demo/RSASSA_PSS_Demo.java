package demo;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author YINYUAN
 * 
 */
public class RSASSA_PSS_Demo {
	
	/*
	 * RSASSA_PKCS_PSS_Demo
	 */
	public static void main(String[] args){
		try {			
			
			final String message = "Hello Cherri. This is my RSA PSS signature demo.";
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
			
			// print result
			System.out.println(String.format("RSA PSS result: %s", result));
			
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
		
		Signature signature = Signature.getInstance("SHA1withRSA/PSS", "BC");
		PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), 32, 1);
		signature.setParameter(pssParameterSpec);
		signature.initSign(privateKey);
		signature.update(message);
		return  signature.sign();
		
	}

	/**
	 * 驗證
	 * 
	 * @param publicKey		公鑰
	 * @param signature		簽章
	 * @param message		傳送的訊息(byte[])
	 * @return true 驗證成功, false 驗證失敗
	 * 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException
	 */
	private static boolean verify(PublicKey publicKey, byte[] signature, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException {
		
		Signature publicSignature = Signature.getInstance("SHA1withRSA/PSS", "BC");
		PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), 32, 1);
		publicSignature.setParameter(pssParameterSpec);
		publicSignature.initVerify(publicKey);
		publicSignature.update(message);
		return publicSignature.verify(signature);
		
	}

}
