package authorisation_server;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ServerSocketFactory;

public class AuthorisationServer {


	static Socket clientSocket;
	static ObjectOutputStream clientOOS;
	static ObjectInputStream clientOIS;
	static Cipher encryptWithWSPublicKey; //TODO Class attributes
	static Cipher decryptWithASPrivateKey;
	static Cipher encryptWithWSSharedKey;
	static int ASid = 42;
	static List<Long> nonces; //list of random "nonces"
	static Key AESKeyWithWS; //TODO TESTING purpose; do it in a better way

	public static void main(String[] args) {
		//TODO TESTING PURPOSES
		//For real AS : additional verifications : 
		//- check if WS_id in the list of WS when receiving STEP 1

		//init Nonces
		nonces = new ArrayList<Long>();


		clientOOS = null;
		clientOIS = null;
		//initiate Socket
		final int PORT = 42000; //AS_PORT TODO TESTING
		ServerSocket serverSocket = null;//TODO TESTING -> class attribut
		boolean successSocket = true;
		ServerSocketFactory servFactory = ServerSocketFactory.getDefault();
		try {
			serverSocket = servFactory.createServerSocket(PORT);
		} catch (IOException e) {
			System.out.println("Auth.Server: error creating server socket:"+e.getMessage());
			successSocket = false;
		} 

		//get connection from WS
		boolean successWS = false;
		if(successSocket) {
			try {
				clientSocket = serverSocket.accept();
				initWSOutputStream();
				System.out.println("Auth.Server: New client connected: "+clientSocket.getInetAddress().toString());
				successWS = true;
			} catch (IOException e) {
				System.out.println("Auth.Server: error accepting WS:"+e.getMessage());
			}
		}

		if(successWS) {
			//NEEDHAM-SCHROEDER protocol (binome du WebService connectToAuthServer())
			boolean success = handshakeWithWS();
			if(success) {
				System.out.println("Shared Key Successfully with WS");
				sendClientInfoToWS();//TODO TESTING; make a proper context call to the function; maybe add some parameters too
				sendClientInfoToWS();//TODO Testing : doesn't add the same client twice :)
			}
			else {
				try {
					clientSocket.close();
				} catch (IOException e) {
					System.out.println("AS : socket closing FAILED");
					e.printStackTrace();
				}
				System.out.println("-_- ............");
			}
		}
	}

	/**
	 * generates the Session Key for WS<->Client, and sends the (client ID, key, cryptoperiod) to WS
	 */
	private static boolean sendClientInfoToWS() {
		int period = 7200; //2h <-> 7200 seconds
		Key clientToWSKey = generateAESKey();
		if(clientToWSKey==null)
			return false;
		int clientID = 720;//TODO TESTING ONLY
		
		//encrypting :
		SealedObject encryptedKey, encryptedClientID, encryptedPeriod;
		try {
			encryptedKey = new SealedObject(clientToWSKey,encryptWithWSSharedKey);
			encryptedClientID = new SealedObject(clientID,encryptWithWSSharedKey);
			encryptedPeriod = new SealedObject(period,encryptWithWSSharedKey);
		} catch (IllegalBlockSizeException e1) {
			System.out.println("Auth.Server: error encrypting Client Info:"+e1.getMessage());
			return false;
		} catch (IOException e1) {
			System.out.println("Auth.Server: error encrypting Client Info:"+e1.getMessage());
			return false;
		}
		//Objects to send :
//		ObjectOutputStream out = getWSOutputStream();
		try {
			ArrayList<Object> message = new ArrayList<Object>();
			message.add(ASid); //0
			message.add(encryptedClientID);//1
			message.add(encryptedKey); //2
			message.add(encryptedPeriod); //3
//			out.writeObject(message);
			clientOOS.writeObject(message);
		} catch (IOException e) {
			System.out.println("Auth.Server: error WS connection: sending client info:"+e.getMessage());
			return false;
		}
		return true;
	}

	//NEEDHAM-SCHROEDER protocol (binome du WebService connectToAuthServer())
	private static boolean handshakeWithWS() {
		//STEP 1
		//receiving objects :
		int WSid;
		SealedObject encryptedWSid, encryptedR1;
		try {
//			ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
			ArrayList<?> message = (ArrayList<?>) clientOIS.readObject();
			WSid = (Integer) message.get(0);
			encryptedWSid = (SealedObject) message.get(1);
			encryptedR1 = (SealedObject) message.get(2);
			Key ASPrivateKey = (Key) message.get(3); //TODO TESTING ONLY
			Key WSPublicKey = (Key) message.get(4); //TODO TESTING ONLY
			initCipher(WSPublicKey);//TODO TESTING ONLY
			initDecipher(ASPrivateKey);//TODO TESTING ONLY

			//			in.close();
		} catch (IOException e) {
			System.out.println("Auth.Server: error WS: receiving step1:"+e.getMessage());
			return false;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return false;
		}
		//decrypting : 
		long decryptedRandom1;
		try {
			int decryptedWSid = (Integer) encryptedWSid.getObject(decryptWithASPrivateKey);
			decryptedRandom1 = (Long) encryptedR1.getObject(decryptWithASPrivateKey);
			//Verification on the WebServer ID
			if(decryptedWSid!=WSid) {
				System.out.println("Auth.Server: Step 1 verification FAILED:");
				System.out.println("WS_ID="+WSid+",encrypted(WS_ID) received="+decryptedWSid);
				return false;
			}
		} catch (IllegalBlockSizeException e) {
			System.out.println("Auth.Server: error AS connection: decrypting step1:"+e.getMessage());
			return false;
		} catch (BadPaddingException e) {
			System.out.println("Auth.Server: error AS connection: decrypting step1:"+e.getMessage());
			return false;
		} catch (IOException e) {
			System.out.println("Auth.Server: error AS connection: decrypting step1:"+e.getMessage());
			return false;
		} catch (ClassNotFoundException e) {
			System.out.println("Auth.Server: error AS connection: decrypting step1:"+e.getMessage());
			return false;
		}
		//end of STEP 1

		//STEP 2
		long random2 = generateNonce();
		//encrypting :
		SealedObject encryptedASid = null;
		SealedObject encryptedRandom1 = null;
		SealedObject encryptedRandom2 = null;
		try {
			encryptedASid = new SealedObject(ASid,encryptWithWSPublicKey);
			encryptedRandom1 = new SealedObject(decryptedRandom1,encryptWithWSPublicKey);
			encryptedRandom2 = new SealedObject(random2,encryptWithWSPublicKey);
		} catch (IllegalBlockSizeException e1) {
			System.out.println("Auth.Server: error encrypting:"+e1.getMessage());
			return false;
		} catch (IOException e1) {
			System.out.println("Auth.Server: error encrypting:"+e1.getMessage());
			return false;
		}
		//Objects to send :
		try {
//			ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
			ArrayList<Object> message = new ArrayList<Object>();
			message.add(encryptedASid); //0
			message.add(encryptedRandom1); //1
			message.add(encryptedRandom2);//2
//			out.writeObject(message); //send the encrypted AS_ID + challenge 1 + challenge2
			clientOOS.writeObject(message);
			//			out.flush();
			//			out.close();
		} catch (IOException e) {
			System.out.println("Auth.Server: error WS connection: sending step2:"+e.getMessage());
			return false;
		}
		//end of STEP 2

		//STEP 3
		try {
//			ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
			long receivedRandom2 = (Long) clientOIS.readObject();
			if(receivedRandom2 != random2) {
				System.out.println("Auth.Server: Step 3 verification FAILED:");
				System.out.println("Random sent="+random2+",random received="+receivedRandom2);
				return false;
			}
			//in.close();
		} catch (IOException e) {
			System.out.println("Auth.Server: error WS: receiving step3:"+e.getMessage());
			return false;
		}
		catch (ClassNotFoundException e) {
			System.out.println("Auth.Server: error Cast step3:"+e.getMessage());
			return false;
		}
		//end of STEP 3

		//STEP 4
		//generate Session Key and send it
		AESKeyWithWS = generateAESKey();
		if(AESKeyWithWS==null)//TODO TESTING only -> proper implement
			return false;
		initAESCipher();
		//encrypting :
		SealedObject encryptedKey = null;
		try {
			encryptedKey = new SealedObject(AESKeyWithWS.getEncoded(),encryptWithWSPublicKey);
		} catch (IllegalBlockSizeException e1) {
			System.out.println("Auth.Server: error encrypting AES key:"+e1.getMessage());
			return false;
		} catch (IOException e1) {
			System.out.println("Auth.Server: error encrypting AES key:"+e1.getMessage());
			return false;
		}
		//Objects to send :
		try {
//			ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
			ArrayList<Object> message = new ArrayList<Object>();
			message.add(encryptedKey); //0
			message.add(encryptedRandom1); //1, already encrypted at step 2
//			out.writeObject(message); //send the encrypted shared key + challenge 1
			clientOOS.writeObject(message);
			//					out.flush();
			//					out.close();
		} catch (IOException e) {
			System.out.println("Auth.Server: error WS connection: sending step4:"+e.getMessage());
			return false;
		}
		//end of STEP 4

		return true;
	}

	private static SecretKey generateAESKey() { //TODO TESTING... comment en pratique?
		try {
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			return kg.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Auth.Server: error Generating AES Key:"+e.getMessage());
			return null;
		}
	}

	static void initCipher(Key WSpublicKey) { //init the cipher/decipher for AS communications (RSA)
		try {
			encryptWithWSPublicKey = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			encryptWithWSPublicKey.init(Cipher.ENCRYPT_MODE, WSpublicKey);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Auth.Server: error RSA cipher init"+e.getMessage());
		} catch (NoSuchPaddingException e) {
			System.out.println("Auth.Server: error RSA cipher init"+e.getMessage());		
		} catch (InvalidKeyException e) {
			System.out.println("Auth.Server: error RSA cipher init"+e.getMessage());
		}
	}
	
	static void initAESCipher() { //init the cipher for communications with WS (AES)
		try {
			encryptWithWSSharedKey = Cipher.getInstance("AES/CBC/PKCS5Padding");
			encryptWithWSSharedKey.init(Cipher.ENCRYPT_MODE, AESKeyWithWS, new IvParameterSpec(new byte[16]));
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Auth.Server: error AES cipher init"+e.getMessage());
		} catch (NoSuchPaddingException e) {
			System.out.println("Auth.Server: error AES cipher init"+e.getMessage());		
		} catch (InvalidKeyException e) {
			System.out.println("Auth.Server: error AES cipher init"+e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("Auth.Server: error AES cipher init"+e.getMessage());
		}
	}

	static void initDecipher(Key ASprivateKey) {
		try {
			decryptWithASPrivateKey = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decryptWithASPrivateKey.init(Cipher.DECRYPT_MODE, ASprivateKey);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Auth.Server: error RSA decipher init"+e.getMessage());
		} catch (NoSuchPaddingException e) {
			System.out.println("Auth.Server: error RSA decipher init"+e.getMessage());		
		} catch (InvalidKeyException e) {
			System.out.println("Auth.Server: error RSA decipher init"+e.getMessage());
		}
	}

	/**
	 * random nonce generator
	 * @return
	 */
	private static long generateNonce() {
		Random generator = new Random();
		Long result = generator.nextLong();
		while(nonces.contains(result)) {
			result = generator.nextLong();
			System.out.println("Auth.Server : SHOULD NOT BE HERE... ELSE, CRAPPY RANDOM GENERATOR");
		}
		System.out.println("Auth.Server : Nonce generated="+result.longValue());
		return result.longValue();
	}
	
	private static void initWSOutputStream() { //TODO rename
		if(clientOOS == null) {
			try {
				clientOOS = new ObjectOutputStream(clientSocket.getOutputStream());
				System.out.println("AS:initialised clientOOS ok");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		if(clientOIS == null) {
			try {
				clientOIS = new ObjectInputStream(clientSocket.getInputStream());
				System.out.println("AS:initialised clientOIS ok");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
//		return clientOOS;
	}
}
