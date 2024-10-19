package de.homelabs.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * ECCCipherTool
 * 
 * Used to encrypt and decrypt messages with the Elliptic Curve Integrated Encryption Scheme
 * and Bouncy Castle Provider  
 * 
 * <b>Note</b>
 * JCE unlimited strength policy must be enabled
 * <code>
 * 	 Security.setProperty("crypto.policy", "unlimited");
 *   int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");  // should be greater than 128
 * </code>
 * 
 * 
 * @see https://www.bouncycastle.org/
 * @see https://de.wikipedia.org/wiki/Elliptic_Curve_Integrated_Encryption_Scheme
 * 
 * @author Dirk Mueller
 * @since 0.1
 *
 */
public class ECIESCipherTool {
	
	KeyPair myKey;
	PublicKey pubKey;
	PrivateKey privKey;
	private Boolean initSuccessfull = false;
	private String exceptionMsg;
	private static final ECIESCipherTool instance = new ECIESCipherTool();
	
	//avoid instantiation
	private ECIESCipherTool() {
		if (!generateKeys())
			initSuccessfull = false;
		else 
			initSuccessfull = true;
	}
	
	/**
	 * get an instance to this class
	 * 
	 * @return ECCCipherTool
	 */
	public static ECIESCipherTool getInstance() {
		return instance;
	}
	
	/**
	 * on instantiation, create private and public ECC / BC key
	 * @return boolean
	 */
	private boolean generateKeys() {
		//enable JCE unlimited strength policy
		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());
		
		KeyPairGenerator keyGen;
		ECGenParameterSpec eccSpec;
		
		try {
			
			keyGen 	= KeyPairGenerator.getInstance("EC", "BC");
			eccSpec = new ECGenParameterSpec("secp256k1");
			keyGen.initialize(eccSpec);
			this.myKey = keyGen.generateKeyPair();
			this.pubKey = myKey.getPublic();
			this.privKey = myKey.getPrivate();
			
			return true;
			
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
			this.exceptionMsg = e.getLocalizedMessage();
			return false;
		}
	}
	
	/**
	 * encrypt message with ECC/BC
	 * 
	 * @param message
	 * @return {@link ECIESCipherResult}
	 */
	public ECIESCipherResult encrypt(String message) {
		if (!initSuccessfull)
			return new ECIESCipherResult(false, this.exceptionMsg, new byte[0]);
		
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("ECIES", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, this.pubKey);
			byte[] encryptedMessage = cipher.doFinal(message.getBytes());
			return new ECIESCipherResult(true, "OK", encryptedMessage);
		} catch (NoSuchAlgorithmException | NoSuchProviderException 
				| NoSuchPaddingException | InvalidKeyException 
				| IllegalBlockSizeException | BadPaddingException e) {
			return new ECIESCipherResult(false, e.getLocalizedMessage(), new byte[0]);		
		}
	}
	
	/**
	 * encrypt message with ECC/BC
	 * 
	 * @param message
	 * @return {@link ECIESCipherResult}
	 */
	public ECIESCipherResult encrypt(byte[] message) {
		if (!initSuccessfull)
			return new ECIESCipherResult(false, this.exceptionMsg, new byte[0]);
		
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("ECIES", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, this.pubKey);
			byte[] encryptedMessage = cipher.doFinal(message);
			return new ECIESCipherResult(true, "OK", encryptedMessage);
		} catch (NoSuchAlgorithmException | NoSuchProviderException 
				| NoSuchPaddingException | InvalidKeyException 
				| IllegalBlockSizeException | BadPaddingException e) {
			return new ECIESCipherResult(false, e.getLocalizedMessage(), new byte[0]);		
		}
	}
	
	/**
	 * decrypt message with ECC/BC
	 * 
	 * @param message
	 * @return {@link ECIESCipherResult}
	 */
	public ECIESCipherResult decrypt(String message) {
		if (!initSuccessfull)
			return new ECIESCipherResult(false, this.exceptionMsg, new byte[0]);
		
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("ECIES", "BC");
			cipher.init(Cipher.DECRYPT_MODE, this.pubKey);
			byte[] encryptedMessage = cipher.doFinal(message.getBytes());
			return new ECIESCipherResult(true, "OK", encryptedMessage);
		} catch (NoSuchAlgorithmException | NoSuchProviderException 
				| NoSuchPaddingException | InvalidKeyException 
				| IllegalBlockSizeException | BadPaddingException e) {
			return new ECIESCipherResult(false, e.getLocalizedMessage(), new byte[0]);		
		}
	}
	
	/**
	 * decrypt message with ECC/BC
	 * 
	 * @param message
	 * @return {@link ECIESCipherResult}
	 */
	public ECIESCipherResult decrypt(byte[] message) {
		if (!initSuccessfull)
			return new ECIESCipherResult(false, this.exceptionMsg, new byte[0]);
		
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("ECIES", "BC");
			cipher.init(Cipher.DECRYPT_MODE, this.pubKey);
			byte[] encryptedMessage = cipher.doFinal(message);
			return new ECIESCipherResult(true, "OK", encryptedMessage);
		} catch (NoSuchAlgorithmException | NoSuchProviderException 
				| NoSuchPaddingException | InvalidKeyException 
				| IllegalBlockSizeException | BadPaddingException e) {
			return new ECIESCipherResult(false, e.getLocalizedMessage(), new byte[0]);		
		}
	}
	
	/**
	 * check if the JCE unlimited strength policy is active
	 * 
	 * @return 0 if exception, 128 if policy is disables else maxAllowedKeyLength
	 */
	public int checkMaxAllowedKeyLength() {
		try {
			return Cipher.getMaxAllowedKeyLength("ECIES");
		} catch (NoSuchAlgorithmException e) {
			return 0;
		}
	}
}
