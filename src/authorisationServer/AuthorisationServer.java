package authorisationServer;


import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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

public class AuthorisationServer implements Runnable{

	private ServerSocket serverSocket;
	private final int PORT = 42000;
	private final int PORT_WS1 = 2013;
	private final int PORT_WS2 = 2014; 
	private final int CLIENT_ID = 10;
	private final int AS_ID = 0;
	private final int WS1_ID = 1;
	private final int WS2_ID = 2;
	private Socket clientSocket;
	private Cipher encryptWithWSPublicKey; //TODO Class attributes
	private Cipher decryptWithASPrivateKey;
	private Cipher encryptWithWSSharedKey;
	private int ASid = 42;
	private List<Long> nonces; //list of random "nonces"
	private Key AESKeyWithWS; //TODO TESTING purpose; do it in a better way
	private PrivateKey ASprivateKey;
	private PublicKey WS1publicKey;
	private PublicKey WS2publicKey;
	
	/**
	 * Map of clients public keys.
	 * Key: client ID
	 * Item: public key of the client
	 */
	private Map<Integer, PublicKey> clientPublicKey;

	private ObjectOutputStream clientOOS;
	private ObjectInputStream clientOIS;
	
	public AuthorisationServer() {

		//init Nonces
		nonces = new ArrayList<Long>();
		//initiate Socket
		ServerSocketFactory servFactory = ServerSocketFactory.getDefault();
		try {
			serverSocket = servFactory.createServerSocket(PORT);
		} catch (IOException e) {
			System.out.println("Auth.Server: error creating server socket:"+e.getMessage());
		} 
	}

	//public static void main(String[] args) {
		//TODO TESTING PURPOSES
		//For real AS : additional verifications : 
		//- check if WS_id in the list of WS when receiving STEP 1

		//get connection from WS

	//}


	private boolean handshakeWithClient(ArrayList<Object> request) throws IOException, ClassNotFoundException {
		//STEP 1
		//receiving objects :
		int requestClientID;//Client ID encapsulated in the request
		int requestWSID;
		SealedObject encryptedClientID, encryptedR3;//encrypted client ID and nonce 3
		
		
		requestClientID = (int)request.get(0);
		requestWSID = (int)request.get(1);
		encryptedClientID = (SealedObject) request.get(2);
		SealedObject encryptedWSID = (SealedObject)request.get(3);
		encryptedR3 = (SealedObject) request.get(4);
		
		//initCipher(WSPublicKey);//TODO TESTING ONLY
		//initDecipher(ASPrivateKey);//TODO TESTING ONLY
		
		//Decrypt
		byte[] r3Challenge = new byte[16];
        r3Challenge = (byte[])RSADecipher(encryptedR3);
        int decryptedClientID = (int)RSADecipher(encryptedClientID);
        int decryptedWSID = (int)RSADecipher(encryptedWSID);
		
		//Verification on the WebServer ID
		if(decryptedClientID != requestClientID || decryptedWSID != requestWSID) {
			System.out.println("Auth.Server: Step 1 verification FAILED:");
			//System.out.println("WS_ID="+requestClient+",encrypted(WS_ID) received="+decryptedWSid);
			return false;
		}
		//end of STEP 1

		//
		//STEP 2
		//
		byte[] r4 = generateNonce();
		
		//encrypting:
		SealedObject encryptedASid = RSACipher(this.AS_ID, this.clientPublicKey.get(requestClientID));
		encryptedWSID = RSACipher(requestWSID, this.clientPublicKey.get(requestClientID));
		SealedObject encryptedNonce3 = RSACipher(r3Challenge, this.clientPublicKey.get(requestClientID));
		SealedObject encryptedNonce4 = RSACipher(r4,this.clientPublicKey.get(requestClientID));
		
		//Objects to send:
		ObjectOutputStream out;
		out = new ObjectOutputStream(clientSocket.getOutputStream());
		ArrayList<Object> message = new ArrayList<Object>();
		message.add(encryptedASid); //0
		message.add(encryptedWSID); //1
		message.add(encryptedNonce3); //2
		message.add(encryptedNonce4);//3
		out.writeObject(message);
		out.flush();
		out.close();
		//end of STEP 2

		//
		//STEP 3
		//
		ObjectInputStream in;
		in = new ObjectInputStream(clientSocket.getInputStream());
		byte[] receivedR4 = (byte[]) in.readObject();
		if(receivedR4 != r4) {
			System.out.println("Auth.Server: Step 3 verification FAILED:");
			//System.out.println("Random sent="+random2+",random received="+receivedRandom2);
			return false;
		}
		in.close();
		//end of STEP 3
		
		return true;
	}
	
	
	/**
	 * generates the Session Key for WS<->Client, and sends the (client ID, key, cryptoperiod) to WS
	 */
	private boolean sendClientInfoToWS() {
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
	private boolean handshakeWithWS() {
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
		byte[] random2 = generateNonce();
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
			byte[] receivedRandom2 = (byte[]) clientOIS.readObject();
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

	private SecretKey generateAESKey() { //TODO TESTING... comment en pratique?
		try {
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			return kg.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Auth.Server: error Generating AES Key:"+e.getMessage());
			return null;
		}
	}

	private void initCipher(Key WSpublicKey) { //init the cipher/decipher for AS communications (RSA)
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
	
	private void initAESCipher() { //init the cipher for communications with WS (AES)
		try {
			this.encryptWithWSSharedKey = Cipher.getInstance("AES/CBC/PKCS5Padding");
			this.encryptWithWSSharedKey.init(Cipher.ENCRYPT_MODE, AESKeyWithWS, new IvParameterSpec(new byte[16]));
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

	private void initDecipher(Key ASprivateKey) {
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
	private byte[] generateNonce() {
		byte[] nonce = new byte[16];
		do {
			Random rand=null;
			try {
				rand = SecureRandom.getInstance("SHA1PRNG");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			rand.nextBytes(nonce);
		} while(nonces.contains(nonce));
		//System.out.println("Auth.Server : Nonce generated="+result.longValue());
		return nonce;
	}
	
	private void initWSOutputStream() { //TODO rename
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

	
	/**
	 * Decipher the given object with the private RSA key of the client.
	 * Note the the method returns an Object, the caller thus has to
	 * know what he expect and cast it.
	 * 
	 * @param ciphered Ciphered object to be deciphered.
	 * @return The deciphered object.
	 */
	private Object RSADecipher(Object ciphered) {
        
        String algo = this.ASprivateKey.getAlgorithm();
		try {
			Cipher ciph = Cipher.getInstance(algo);
			ciph.init(Cipher.DECRYPT_MODE, this.ASprivateKey);
			return (Object)((SealedObject) ciphered).getObject(ciph);
		} catch (ClassNotFoundException | IllegalBlockSizeException
				| BadPaddingException | IOException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private SealedObject RSACipher(Serializable toBeCiphered, Key pubKey) {
		Cipher ciph;
		try {
			ciph = Cipher.getInstance("RSA");
			ciph.init(Cipher.ENCRYPT_MODE, pubKey);
			return new SealedObject(toBeCiphered, ciph);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException | IllegalBlockSizeException | IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private void sendAESKeyToClient() {
		
	}
	@Override
	public void run() {
		
		while(true) {
			boolean clientConnected = false;
			try {
				clientSocket = serverSocket.accept();
				System.out.println("Auth.Server: New client connected: "+clientSocket.getInetAddress().toString());
				clientConnected = true;
				if(clientConnected) {
					ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream()); 
					ArrayList<Object> distantObjects = new ArrayList<Object>();
					distantObjects = (ArrayList<Object>)ois.readObject();
					
					int acceptedID = (int)distantObjects.get(0);
					if(acceptedID == this.CLIENT_ID) {//We have a user
						if(handshakeWithClient(distantObjects)) {
							sendAESKeyToClient();
						}
					}
					else if(acceptedID == this.PORT_WS1) {//First WS
						handshakeWithWS();
					}
					else if(acceptedID == this.PORT_WS2) {//Second WS
						handshakeWithWS();
					}
					
					boolean success = handshakeWithWS();
					if(success)
						System.out.println("Shared Key Successfully with WS");
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
			} catch (IOException | ClassNotFoundException e) {
				System.out.println("Auth.Server: error accepting WS:"+e.getMessage());
			}
		}
		
	}
}
