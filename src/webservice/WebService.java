package webservice;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;

public abstract class WebService implements Runnable {

	//AS informations
	protected final static String ASaddress = "localhost";
	protected final static int ASport = 42000;
	protected final static int ASid = 42;
	protected static Key ASpublicKey; //TODO recuperer la cle publique depuis le .pem
	protected static Key ASprivateKey;//TODO TESTING ONLY
	
	protected Key sharedWithASKey; //AES key between AS and WS
	protected Key WSpublicKey;//TODO recuperer la cle publique depuis le .pem ??
	protected Key WSprivateKey;//TODO recuperer la cle publique depuis le .pem
	protected Cipher encryptWithASPublicKey;
	protected Cipher decryptWithWSPrivateKey;
	protected Cipher decryptWithASSharedKey;

	protected final int webID; //web service ID
	protected final int PORT;
	protected ServerSocket serverSocket;
	protected Socket ASsocket;
	
	protected List<Integer> clientIDList;
	protected List<Key> clientKeyList;
	protected List<Integer> clientPeriodList;

	private static List<Long> nonces; //list of random "nonces"

	protected WebService(int port, int ID) {
		//init variables
		nonces = new ArrayList<Long>();
		this.clientIDList = new ArrayList<Integer>();
		this.clientKeyList = new ArrayList<Key>();
		this.clientPeriodList = new ArrayList<Integer>();
		this.PORT = port;
		this.webID = ID;
		ServerSocketFactory servFactory = ServerSocketFactory.getDefault();
		//TODO test purposes***:
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			KeyPair kp = kpg.generateKeyPair();
			PublicKey pubKey = kp.getPublic();
			ASpublicKey = pubKey;
			PrivateKey privKey = kp.getPrivate();
			ASprivateKey = privKey;

			kp = kpg.generateKeyPair();
			this.WSpublicKey = kp.getPublic();
			this.WSprivateKey = kp.getPrivate();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		//**end of test purposes 

		//init server socket
		boolean successSocket = true;
		try {
			this.serverSocket = servFactory.createServerSocket(PORT);
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error creating server socket:"+e.getMessage());
			successSocket = false;
		} 

		//init the cipher/decipher for AS communications (RSA)
		try {
			this.encryptWithASPublicKey = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			this.encryptWithASPublicKey.init(Cipher.ENCRYPT_MODE, ASpublicKey);
			this.decryptWithWSPrivateKey = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			this.decryptWithWSPrivateKey.init(Cipher.DECRYPT_MODE, this.WSprivateKey);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("WEBSERVICE: error RSA encryption"+e.getMessage());
		} catch (NoSuchPaddingException e) {
			System.out.println("WEBSERVICE: error RSA encryption"+e.getMessage());		
		} catch (InvalidKeyException e) {
			System.out.println("WEBSERVICE: error RSA encryption"+e.getMessage());
		}

		//try to connect to AS
		boolean successAS = false;
		if(successSocket) {
			successAS = this.connectToAuthServer();
		}
		if(successAS) {
			System.out.println("WEBSERVICE: connected to AS successfully");
			this.mainLoop(); //enter main loop
		} else {
			System.out.println("WEBSERVICE: could not connect to AS");
		}
	}

	/**
	 * essaie d'etablir la connexion avec le AS
	 * @return vrai ou faux suivant si succes ou pas (du protocole)
	 */
	private boolean connectToAuthServer() { //TODO ajouter/revoir le socket.close() et les IOstream.close()
		//initialise le socket "client" pour se connecter a l'AS
		SocketFactory ASfactory = SocketFactory.getDefault();
		try {
			this.ASsocket = ASfactory.createSocket(ASaddress,ASport);
		} catch (UnknownHostException e) {
			System.out.println("WEBSERVICE: error connecting to AS:"+e.getMessage());
			return false;
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error creating client socket for AS:"+e.getMessage());
			return false;
		}

		//Needham-Schroeder protocol between WS and AS
		//STEP 1:
		long random1 = generateNonce();
		//encrypting :
		SealedObject encryptedWSid =null;
		SealedObject encryptedNonce =null;
		try {
			encryptedWSid = new SealedObject(this.webID,this.encryptWithASPublicKey);
			encryptedNonce = new SealedObject(random1,this.encryptWithASPublicKey);
		} catch (IllegalBlockSizeException e1) {
			System.out.println("WEBSERVICE: error encrypting:"+e1.getMessage());
			return false;
		} catch (IOException e1) {
			System.out.println("WEBSERVICE: error encrypting:"+e1.getMessage());
			return false;
		}
		//Objects to send :
		try {
			ObjectOutputStream out = new ObjectOutputStream(ASsocket.getOutputStream());
			ArrayList<Object> message = new ArrayList<Object>();
			message.add(this.webID); //0
			message.add(encryptedWSid); //1
			message.add(encryptedNonce); //2
			message.add(ASprivateKey);//3 TODO TESTING only
			message.add(this.WSpublicKey); //4 TODO TESTING ONLY
			out.writeObject(message); //send the ID and the encrypted ID+challenge
//			out.flush();
//			out.close();
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error AS connection: sending step1:"+e.getMessage());
			return false;
		}
		//end of STEP 1

		//STEP 2:
		//receiving objects :
		SealedObject encryptedASid, encryptedR1, encryptedR2;
		try {
			ObjectInputStream in = new ObjectInputStream(ASsocket.getInputStream());
			ArrayList<?> message = (ArrayList<?>) in.readObject();
			encryptedASid = (SealedObject) message.get(0);
			encryptedR1 = (SealedObject) message.get(1);
			encryptedR2 = (SealedObject) message.get(2);
//			in.close();
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error AS connection: receiving step2:"+e.getMessage());
			return false;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return false;
		}
		//decrypting : 
		long decryptedRandom2;
		try {
			int decryptedASid = (Integer) encryptedASid.getObject(this.decryptWithWSPrivateKey);
			long decryptedRandom1 = (Long) encryptedR1.getObject(this.decryptWithWSPrivateKey);
			decryptedRandom2 = (Long) encryptedR2.getObject(this.decryptWithWSPrivateKey);
			if(decryptedRandom1!=random1 || decryptedASid!=ASid) {
				System.out.println("WEBSERVICE: Step 2 verification FAILED:");
				System.out.println("Random sent="+random1+",random received="+decryptedRandom1);
				System.out.println("AS_ID="+ASid+",AS_ID received="+decryptedASid);
				return false;
			}
		} catch (IllegalBlockSizeException e) {
			System.out.println("WEBSERVICE: error AS connection: decrypting step2:"+e.getMessage());
			return false;
		} catch (BadPaddingException e) {
			System.out.println("WEBSERVICE: error AS connection: decrypting step2:"+e.getMessage());
			return false;
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error AS connection: decrypting step2:"+e.getMessage());
			return false;
		} catch (ClassNotFoundException e) {
			System.out.println("WEBSERVICE: error AS connection: decrypting step2:"+e.getMessage());
			return false;
		}
		//end of STEP 2
		
		//STEP 3
		//Send random2 back :
		try {
			ObjectOutputStream out = new ObjectOutputStream(ASsocket.getOutputStream());
			out.writeObject(decryptedRandom2);
//			out.flush();
//			out.close();
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error AS connection: sending step3:"+e.getMessage());
			return false;
		}
		//end of STEP 3
		
		//STEP 4
		//receiving objects :
		SealedObject encryptedKey, encryptedR1bis;
		try {
			ObjectInputStream in = new ObjectInputStream(ASsocket.getInputStream());
			ArrayList<?> message = (ArrayList<?>) in.readObject();
			encryptedKey = (SealedObject) message.get(0);
			encryptedR1bis = (SealedObject) message.get(1);
//			in.close();
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error AS connection: receiving step 4:"+e.getMessage());
			return false;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return false;
		}
		//decrypting : 
		Key decryptedKey;
		try { //BEWARE : encrypted key is in raw format (aka byte[])
			byte[] rawKey = (byte[]) encryptedKey.getObject(this.decryptWithWSPrivateKey);
			decryptedKey = new SecretKeySpec(rawKey,"AES");
//			decryptedKey = (Key) encryptedKey.getObject(this.decryptWithWSPrivateKey);
			long decryptedRandom1bis = (Long) encryptedR1bis.getObject(this.decryptWithWSPrivateKey);
			if(decryptedRandom1bis != random1) {
				System.out.println("WEBSERVICE: Step 4 verification FAILED:");
				System.out.println("Random sent="+random1+",random received="+decryptedRandom1bis);
				return false;
			}
		} catch (IllegalBlockSizeException e) {
			System.out.println("WEBSERVICE: error AS connection: decrypting step4:"+e.getMessage());
			return false;
		} catch (BadPaddingException e) {
			System.out.println("WEBSERVICE: error AS connection: decrypting step4:"+e.getMessage());
			return false;
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error AS connection: decrypting step4:"+e.getMessage());
			return false;
		} catch (ClassNotFoundException e) {
			System.out.println("WEBSERVICE: error AS connection: decrypting step4:"+e.getMessage());
			return false;
		}
		
		this.sharedWithASKey = decryptedKey;
		this.initDecryptWithSharedKey();
		//end of STEP 4

		return true;
	}

	/**
	 * initialise the cipher used to decrypt messages from the AS, using the shared AES key
	 * TODO modify code for the AES decryption (bytes, IV, ...)
	 */
	private void initDecryptWithSharedKey() {
		try {
			this.decryptWithASSharedKey = Cipher.getInstance("AES/CBC/PKCS5Padding");
			this.decryptWithASSharedKey.init(Cipher.DECRYPT_MODE, this.sharedWithASKey);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("WebThread: error AES decryption:"+e.getMessage());
		} catch (NoSuchPaddingException e) {
			System.out.println("WebThread: error AES decryption:"+e.getMessage());		
		} catch (InvalidKeyException e) {
			System.out.println("WebThread: error AES decryption:"+e.getMessage());
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
			System.out.println("WebServer : SHOULD NOT BE HERE... ELSE, CRAPPY RANDOM GENERATOR");
		}
		System.out.println("WebServer : Nonce generated="+result.longValue());
		return result.longValue();
	}

	/**
	 * recoit de l'AS les infos du client qui veut se connecter :
	 * - ID du client
	 * - la cle partagee entre WS et Client
	 * - la cryptoperiode de la cle
	 * 
	 * TODO N.B. En pratique, il serait peut-etre plus utile de garder la liste sur disque dur?
	 */
	private void addNewClientInfo(int ID, Key sharedKey, int period) {
		if(! this.clientIDList.contains(ID)) {
			this.clientIDList.add(ID);
			this.clientKeyList.add(sharedKey);
			this.clientPeriodList.add(period);
		}
	}

	/**
	 * recoit la requete chiffree du client, la dechiffre, et repond avec le service demande
	 */
	protected abstract void answerClientRequest();

	/**
	 * boucle principale du serveur :
	 * - cree un thread pour ajouter les infos venant de l'AS
	 * - thread principal : gere le client
	 */
	private void mainLoop() {//TODO uncomment
		//		new Thread(this).start(); //lance le thread AS <-> WS
		//		while(true) { //recoit une connexion et la traite
		//this.answerClientRequest();
		//		}
	}

	/**
	 * Thread qui s'occupe de rajouter les infos des nouveaux clients, recues de l'AS
	 */
	@Override
	public void run() {
		System.out.println("Starting thread AS<->WS");
		
		//init input stream
		ObjectInputStream receiveFromAS = null;
		try {
			receiveFromAS = new ObjectInputStream(ASsocket.getInputStream());
		} catch (IOException e) {
			System.out.println("WebService Thread: error Getting input stream:"+e.getMessage());
		}
		
		//init variables
		Object received;
		boolean exit = false;
		int idFromAS;
		SealedObject encryptedClientID, encryptedClientSharedKey, encryptedCryptoperiod;
		int clientID, cryptoperiod;
		Key clientSharedKey;
		//while connection with AS
		while(!exit) {
			System.out.println("WebThread while loop");
			try {
				//read message
				received=receiveFromAS.readObject();
				//get informations
				ArrayList<?> message = (ArrayList<?>) received;
				idFromAS = (Integer) message.get(0);
				if(idFromAS == ASid) {
					encryptedClientID = (SealedObject) message.get(1);
					encryptedClientSharedKey = (SealedObject) message.get(2);
					encryptedCryptoperiod = (SealedObject) message.get(3);
					//decrypt info
					clientID = (Integer) encryptedClientID.getObject(this.decryptWithASSharedKey);
					clientSharedKey = (Key) encryptedClientSharedKey.getObject(this.decryptWithASSharedKey);
					cryptoperiod = (Integer) encryptedCryptoperiod.getObject(this.decryptWithASSharedKey);
					//store them
					this.addNewClientInfo(clientID,clientSharedKey,cryptoperiod);
				} else
					exit = true;
			} catch (IOException e) {
				System.out.println("WebThread reading IO error"+e.getMessage());
				exit = true;
			} catch (ClassNotFoundException e) {
				System.out.println("WebThread Class not found"+e.getMessage());
				exit = true;
			} catch (IllegalBlockSizeException e) {
				System.out.println("WebThread illegal block size error"+e.getMessage());
				exit = true;
			} catch (BadPaddingException e) {
				System.out.println("WebThread bad padding error"+e.getMessage());
				exit = true;
			}
		}
		
		try {
			receiveFromAS.close();
			System.out.println("WebThread : closing AS socket");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
