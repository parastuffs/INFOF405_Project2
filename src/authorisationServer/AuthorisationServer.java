package authorisationServer;


import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
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
import javax.xml.bind.DatatypeConverter;

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
	private List<byte[]> nonces; //list of random "nonces"
	private Key fromAStoWSKey; //TODO TESTING purpose; do it in a better way
	private PrivateKey ASprivateKey;
	private PublicKey WS1publicKey;
	private PublicKey WS2publicKey;
	private final int CRYPTOPERIOD = 7200;//2 hours <->7200 seconds
	private Key clientToWSKey;
	//TODO for testing, remove when DB OK
	private final String PUBLICKEYFILE_CLIENT = "certs/key.CL1.public.pem";
	private final String PRIVATEKEYFILE_AS = "certs/key.AS.priv.pem";
	
	/**
	 * Map of clients public keys.
	 * Key: client ID
	 * Item: public key of the client
	 */
	private Map<Integer, PublicKey> clientPublicKey;
	
	private final int CLIENTID = 10;

	private ObjectOutputStream clientOOS = null;
	private ObjectInputStream clientOIS=null;
	private ObjectOutputStream ws1OOS = null;
//	private ObjectInputStream ws1OIS = null;
	
	public AuthorisationServer(Socket socket) {

		this.clientSocket = socket;
		this.initObjectIOStream();
		//init Nonces
		nonces = new ArrayList<byte[]>();
		
		//Load keys
		PublicKey temp = loadPublicKey(this.PUBLICKEYFILE_CLIENT, "RSA");
		if(temp == null) System.out.println("bite");
		this.clientPublicKey = new HashMap<Integer, PublicKey>();
		this.clientPublicKey.put(this.CLIENTID, temp);
		this.ASprivateKey = loadPrivateKey(this.PRIVATEKEYFILE_AS, "RSA");
		
		//initiate Socket
//		ServerSocketFactory servFactory = ServerSocketFactory.getDefault();
//		try {
//			serverSocket = servFactory.createServerSocket(PORT);
//		} catch (IOException e) {
//			System.out.println("Auth.Server: error creating server socket:"+e.getMessage());
//		} 
	}

	private void initObjectIOStream() {
		if(this.clientOOS == null) {
			try {
				this.clientOOS = new ObjectOutputStream(clientSocket.getOutputStream());
				System.out.println("AS:initialised clientOOS ok");
				this.clientOOS.flush();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		if(this.clientOIS == null) {
			try {
				this.clientOIS = new ObjectInputStream(clientSocket.getInputStream());
				System.out.println("AS:initialised clientOIS ok");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	private void closeObjectIOStream() {
		System.out.println("AS: closing IO streams");
		if(this.clientOIS!=null)
			try {
				this.clientOIS.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		if(this.clientOOS!=null)
			try {
				this.clientOOS.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
	}
	/**
	 * Method loading the private keys from the .pem file.
	 * @param filename .pem file containing the key
	 */
	private PrivateKey loadPrivateKey(String filename, String algo) {
		File f = new File(filename);
		FileInputStream fis;
		try {
			fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			byte[] keyBytes = new byte[(int) f.length()];
			dis.readFully(keyBytes);
			dis.close();

			String temp = new String(keyBytes);
			String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----\n", "");
			privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
			//System.out.println("Private key\n"+privKeyPEM);
			byte[] decoded = DatatypeConverter.parseBase64Binary(privKeyPEM);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
			KeyFactory kf = KeyFactory.getInstance(algo);
			return kf.generatePrivate(spec);	
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * Method loading the public key from the .pem file.
	 * @param filename .pem file containing the key
	 */
	private PublicKey loadPublicKey(String filename, String algo) {
		File f = new File(filename);
		FileInputStream fis;
		try {
			fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			byte[] keyBytes = new byte[(int) f.length()];
			dis.readFully(keyBytes);
			dis.close();
			
			String temp = new String(keyBytes);
			String publicKeyPEM = temp.replace("-----BEGIN PUBLIC KEY-----\n", "");
			publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
			byte[] decoded = DatatypeConverter.parseBase64Binary(publicKeyPEM);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
			KeyFactory kf = KeyFactory.getInstance(algo);
			return kf.generatePublic(spec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	

	private boolean handshakeWithClient(ArrayList<Object> request, ObjectInputStream ois) throws IOException, ClassNotFoundException {
		//STEP 1
		System.out.println("Beginning of step 1");
		//receiving objects :
		int requestClientID;//Client ID encapsulated in the request
		int requestWSID;
		SealedObject encryptedClientID, encryptedR3;//encrypted client ID and nonce 3
		
		
		requestClientID = (int)request.get(0);
		
		//TODO AJOUT aller chercher cle RSA du client ICI
		
		
		//System.out.println("requestClientID="+requestClientID);
		requestWSID = (int)request.get(1);
		
		//TODO AJOUT regarder si le client peut acceder a WS1, bloquer si necessaire
		
		//System.out.println("requestWSID="+requestWSID);
		encryptedClientID = (SealedObject)request.get(2);
		SealedObject encryptedWSID = (SealedObject)request.get(3);
		encryptedR3 = (SealedObject)request.get(4);
		
		//Decrypt
		byte[] r3Challenge = new byte[16];
        r3Challenge = (byte[])RSADecipher(encryptedR3);
        //System.out.println("r3Challenge: "+new String(r3Challenge, "UTF-8"));
        int decryptedClientID = (int)RSADecipher(encryptedClientID);
        //System.out.println("decryptedClientID="+decryptedClientID);
        int decryptedWSID = (int)RSADecipher(encryptedWSID);
        //System.out.println("decryptedWSID="+decryptedWSID);
		
		//Verification on the WebServer ID and client ID
		if(decryptedClientID != requestClientID || decryptedWSID != requestWSID) {
			System.out.println("Auth.Server: Step 1 verification FAILED:");
			System.out.println("WS_ID="+requestWSID+",encrypted(WS_ID) received="+decryptedWSID);
			System.out.println("Client ID="+requestClientID+",encrypted(Client ID) received="+decryptedClientID);
			return false;
		}
		System.out.println("End of step 1");
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
//		ObjectOutputStream out;
//		out = new ObjectOutputStream(clientSocket.getOutputStream());
		ArrayList<Object> message = new ArrayList<Object>();
		message.add(encryptedASid); //0
		message.add(encryptedWSID); //1
		message.add(encryptedNonce3); //2
		message.add(encryptedNonce4);//3
//		out.writeObject(message);
//		out.flush();
		this.clientOOS.writeObject(message);
		this.clientOOS.flush();
		System.out.println("End of step 2");
		//end of STEP 2

		//
		//STEP 3
		//
		//Note: we can't open multiple ObjectInputStream on a socket.
//		byte[] receivedR4 = (byte[]) ois.readObject();
		byte[] receivedR4 = (byte[]) this.clientOIS.readObject();
		if(!Arrays.equals(receivedR4, r4)) {
			System.out.println("Auth.Server: Step 3 verification FAILED:");
			//System.out.println("Random sent="+random2+",random received="+receivedRandom2);
			return false;
		}
		System.out.println("End of step 3");
		//end of STEP 3
		
		System.out.println("So far, so good. We will now send the key to the client.");
		
		//
		//Now, send the symetric key to the client.
		//
		this.clientToWSKey = generateAESKey();
//		sendAESKeyToClient(r3Challenge, requestClientID, out);
		sendAESKeyToClient(r3Challenge, requestClientID, this.clientOOS);
		sendClientInfoToWS(requestClientID);//TODO add server outstream

//		out.close();
		this.closeObjectIOStream();
		
		return true;
	}
	
	/**
	 * generates the Session Key for WS<->Client, and sends the (client ID, key, cryptoperiod) to WS
	 */
	private boolean sendClientInfoToWS(int clientID) {
		int period = CRYPTOPERIOD;
		if(clientToWSKey==null)
			return false;
//		int clientID = 720;//TODO TESTING ONLY
		System.out.println("Preparing to sent Client info to WS");
		System.out.println("OOS client="+clientOOS.toString()+",ws="+ws1OOS.toString());
		//encrypting :
		SealedObject encryptedKey, encryptedClientID, encryptedPeriod;
		try {
			encryptedKey = new SealedObject(clientToWSKey.getEncoded(),encryptWithWSSharedKey); //TODO need to Key.getEncoded()?
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
			message.add(this.AS_ID); //0
			message.add(encryptedClientID);//1
			message.add(encryptedKey); //2
			message.add(encryptedPeriod); //3
//			out.writeObject(message);
			ws1OOS.writeObject(message);
			ws1OOS.flush();
		} catch (IOException e) {
			System.out.println("Auth.Server: error WS connection: sending client info:"+e.getMessage());
			return false;
		}
		System.out.println("AS: Key sent to WS");
		return true;
	}

	//NEEDHAM-SCHROEDER protocol (binome du WebService connectToAuthServer())
	private boolean handshakeWithWS(ArrayList<Object> request) {
		System.out.println("Starting handshake with WS");
		//STEP 1
		//receiving objects :
		int WSid;
		SealedObject encryptedWSid, encryptedR1;
//		try {
//			ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
//			ArrayList<?> message = (ArrayList<?>) clientOIS.readObject();
			ArrayList<?> message1 = request;
			WSid = (Integer) message1.get(0);
			encryptedWSid = (SealedObject) message1.get(1);
			encryptedR1 = (SealedObject) message1.get(2);
			Key ASPrivateKey = (Key) message1.get(3); //TODO TESTING ONLY
			Key WSPublicKey = (Key) message1.get(4); //TODO TESTING ONLY
			initCipher(WSPublicKey);//TODO TESTING ONLY
			initDecipher(ASPrivateKey);//TODO TESTING ONLY

			//			in.close();
//		} catch (IOException e) {
//			System.out.println("Auth.Server: error WS: receiving step1:"+e.getMessage());
//			return false;
//		} catch (ClassNotFoundException e) {
//			e.printStackTrace();
//			return false;
//		}
		//decrypting : 
		byte[] decryptedRandom1;
		try {
			int decryptedWSid = (Integer) encryptedWSid.getObject(decryptWithASPrivateKey);
			decryptedRandom1 = (byte[]) encryptedR1.getObject(decryptWithASPrivateKey);
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
		System.out.println("Step 1 - ok");
		//STEP 2
		byte[] random2 = generateNonce();
		//encrypting :
		SealedObject encryptedASid = null;
		SealedObject encryptedRandom1 = null;
		SealedObject encryptedRandom2 = null;
		try {
			encryptedASid = new SealedObject(this.AS_ID,encryptWithWSPublicKey);
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
			ArrayList<Object> message2 = new ArrayList<Object>();
			message2.add(encryptedASid); //0
			message2.add(encryptedRandom1); //1
			message2.add(encryptedRandom2);//2
//			out.writeObject(message); //send the encrypted AS_ID + challenge 1 + challenge2
			clientOOS.writeObject(message2);
			//			out.flush();
			//			out.close();
		} catch (IOException e) {
			System.out.println("Auth.Server: error WS connection: sending step2:"+e.getMessage());
			return false;
		}
		//end of STEP 2
		System.out.println("Step 2 - ok");
		//STEP 3
		try {
//			ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
			byte[] receivedRandom2 = (byte[]) clientOIS.readObject();
			if(!this.compare(receivedRandom2,random2)) {
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
		System.out.println("Step 3 - ok");
		//STEP 4
		//generate Session Key and send it
		fromAStoWSKey = generateAESKey();
		if(fromAStoWSKey==null)//TODO TESTING only -> proper implement
			return false;
		initAESCipher();
		//encrypting :
		SealedObject encryptedKey = null;
		try {
			encryptedKey = new SealedObject(fromAStoWSKey.getEncoded(),encryptWithWSPublicKey);
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
			ArrayList<Object> message4 = new ArrayList<Object>();
			message4.add(encryptedKey); //0
			message4.add(encryptedRandom1); //1, already encrypted at step 2
//			out.writeObject(message); //send the encrypted shared key + challenge 1
			clientOOS.writeObject(message4);
			//					out.flush();
			//					out.close();
		} catch (IOException e) {
			System.out.println("Auth.Server: error WS connection: sending step4:"+e.getMessage());
			return false;
		}
		//end of STEP 4
		System.out.println("Step 4 - ok; Handshake was successfull");
		return true;
	}
	
	private boolean compare(byte[] a, byte[] b) {
		if(a.length != b.length) {
			System.out.println("compare A B: length diff"+a.length+"<->"+b.length);
			return false;
		}
		boolean res = true;
		for(int i=0;i<a.length;i++) {
			if(a[i]!=b[i])
				res = false;
		}
		return res;
	}
	
	private SecretKey generateAESKey() { //TODO TESTING... comment en pratique?
		try {
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(128);
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
			this.encryptWithWSSharedKey.init(Cipher.ENCRYPT_MODE, fromAStoWSKey, new IvParameterSpec(new byte[16]));
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


	
	/**
	 * Decipher the given object with the private RSA key of the client.
	 * Note the the method returns an Object, the caller thus has to
	 * know what he expect and cast it.
	 * 
	 * @param ciphered Ciphered object to be deciphered.
	 * @return The deciphered object.
	 */
	private Object RSADecipher(Object ciphered) {
        
        String algo = this.ASprivateKey.getAlgorithm();//RSA
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
	
	private void sendAESKeyToClient(byte[] r3, int clientID, ObjectOutputStream oos) {
		
		//encrypting:
		SealedObject encryptedKey, encryptedR3, encryptedPeriod;
		encryptedKey = RSACipher(clientToWSKey.getEncoded(), this.clientPublicKey.get(clientID));
		//byte[] bite = new byte[16];
		//encryptedKey = RSACipher(encryptedKey, this.clientPublicKey.get(clientID));
		//encryptedKey = RSACipher(clientToWSKey.getEncoded(), this.clientPublicKey.get(clientID));
		encryptedR3 = RSACipher(r3, this.clientPublicKey.get(clientID));
		encryptedPeriod = RSACipher(this.CRYPTOPERIOD, this.clientPublicKey.get(clientID));
		
		//Objects to send:
		ArrayList<Object> message = new ArrayList<Object>();
		message.add(encryptedKey);//0
		message.add(encryptedPeriod); //1
		message.add(encryptedR3);//2
		try {
			oos.writeObject(message);
			System.out.println("Key sent to the client.");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	@SuppressWarnings("unchecked")
	@Override
	public void run() {
		
		//while(true) {
			try {
				//System.out.println("Waiting for a new connection.");
				//clientSocket = serverSocket.accept();
				//System.out.println("Auth.Server: New client connected: "+clientSocket.getInetAddress().toString());
				
//				ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
//				oos.flush();
//				ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream()); 
				ArrayList<Object> distantObjects = new ArrayList<Object>();
//				distantObjects = (ArrayList<Object>) ois.readObject();
				distantObjects = (ArrayList<Object>) this.clientOIS.readObject();
				int acceptedID = (int)distantObjects.get(0);
				if(acceptedID == this.CLIENT_ID) {//We have a user
					System.out.println("We have a client, here!");
					//ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
					//Thread tClient = new Thread(new ClientHandler(clientSocket, ois));
					//tClient.start();
//					handshakeWithClient(distantObjects, ois);
					handshakeWithClient(distantObjects, this.clientOIS);
				}
				else if(acceptedID == this.WS1_ID) {//First WS
					System.out.println("Accepting WS1");
//					this.ws1OOS = this.clientOOS;
//					this.clientOOS.close();
//					this.ws1OOS = new ObjectOutputStream(clientSocket.getOutputStream());
					handshakeWithWS(distantObjects);
				}
				else if(acceptedID == this.WS2_ID) {//Second WS
					System.out.println("Accepting WS2");
					handshakeWithWS(distantObjects);
				}
				//clientSocket.close();
			} catch (IOException | ClassNotFoundException e) {
				System.out.println("Auth.Server: error accepting WS:"+e.getMessage());
				e.printStackTrace();
			}
		//}
		
	}
}
