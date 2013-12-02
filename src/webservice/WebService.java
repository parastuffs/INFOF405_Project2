package webservice;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;

public abstract class WebService implements Runnable {

	//AS informations
	protected final static String ASaddress = "localhost";
	protected final static int ASport = 42000;
	protected final static int ASid = 0;
	protected static Key ASpublicKey; //TODO recuperer la cle publique depuis le .pem
	protected static Key ASprivateKey;//TODO TESTING ONLY
	
	protected Key sharedWithASKey; //AES key between AS and WS
	protected Key WSpublicKey;//TODO recuperer la cle publique depuis le .pem ??
	protected Key WSprivateKey;//TODO recuperer la cle publique depuis le .pem
	protected Cipher encryptWithASPublicKey;
	protected Cipher decryptWithWSPrivateKey;
	protected Cipher decryptWithASSharedKey;
	protected static final int ENCRYPT = 0;
	protected static final int DECRYPT = 1;

	protected final int webID; //web service ID
	protected final int PORT;
	protected ServerSocket serverSocket;
	protected Socket ASsocket;
	private ObjectInputStream ASSocketOIS;
	private ObjectOutputStream ASSocketOOS;
	
	protected List<Integer> clientIDList;
	protected List<Key> clientKeyList;
	protected List<Long> clientPeriodList;

	private static List<byte[]> nonces; //list of random "nonces"

	/**
	 * Constructor : initialise les variables, puis essaie de se connecter à l'AS, et si ça marche, 
	 * entre dans la boucle principale
	 * @param port Port utilisé par le service; 2013 si blackboard, 2014 si keychain
	 * @param ID l'ID du service : blackboard=0, keychain=1
	 */
	protected WebService(int port, int ID) {
		//init variables
		nonces = new ArrayList<byte[]>();
		this.clientIDList = new ArrayList<Integer>();
		this.clientKeyList = new ArrayList<Key>();
		this.clientPeriodList = new ArrayList<Long>();
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
			this.initASObjectIOStream();
		} catch (UnknownHostException e) {
			System.out.println("WEBSERVICE: error connecting to AS:"+e.getMessage());
			return false;
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error creating client socket for AS:"+e.getMessage());
			return false;
		}

		System.out.println("Starting handshake with AS");
		//Needham-Schroeder protocol between WS and AS
		//STEP 1:
		byte[] random1 = generateNonce();
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
//			ObjectOutputStream out = new ObjectOutputStream(ASsocket.getOutputStream());
			ArrayList<Object> message = new ArrayList<Object>();
			message.add(this.webID); //0
			message.add(encryptedWSid); //1
			message.add(encryptedNonce); //2
			message.add(ASprivateKey);//3 TODO TESTING only
			message.add(this.WSpublicKey); //4 TODO TESTING ONLY
//			out.writeObject(message); //send the ID and the encrypted ID+challenge
			this.ASSocketOOS.writeObject(message);
//			this.ASSocketOOS.flush();
//			out.flush();
//			out.close();
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error AS connection: sending step1:"+e.getMessage());
			return false;
		}
		//end of STEP 1
		System.out.println("Step1 ok");
		//STEP 2:
		//receiving objects :
		SealedObject encryptedASid, encryptedR1, encryptedR2;
		try {
//			ObjectInputStream in = new ObjectInputStream(ASsocket.getInputStream());
//			ArrayList<?> message = (ArrayList<?>) in.readObject();
			ArrayList<?> message = (ArrayList<?>) this.ASSocketOIS.readObject();
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
		byte[] decryptedRandom2;
		try {
			int decryptedASid = (Integer) encryptedASid.getObject(this.decryptWithWSPrivateKey);
			byte[] decryptedRandom1 = (byte[]) encryptedR1.getObject(this.decryptWithWSPrivateKey);
			decryptedRandom2 = (byte[]) encryptedR2.getObject(this.decryptWithWSPrivateKey);
			if(!this.compare(decryptedRandom1,random1) || decryptedASid!=ASid) {
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
		System.out.println("step2 ok");
		//STEP 3
		//Send random2 back :
		try {
//			ObjectOutputStream out = new ObjectOutputStream(ASsocket.getOutputStream());
//			out.writeObject(decryptedRandom2);
			this.ASSocketOOS.writeObject(decryptedRandom2);
			this.ASSocketOOS.flush();
//			out.close();
		} catch (IOException e) {
			System.out.println("WEBSERVICE: error AS connection: sending step3:"+e.getMessage());
			return false;
		}
		//end of STEP 3
		System.out.println("step3 ok");
		//STEP 4
		//receiving objects :
		SealedObject encryptedKey, encryptedR1bis;
		try {
//			ObjectInputStream in = new ObjectInputStream(ASsocket.getInputStream());
//			ArrayList<?> message = (ArrayList<?>) in.readObject();
			ArrayList<?> message = (ArrayList<?>) ASSocketOIS.readObject();
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
			byte[] decryptedRandom1bis = (byte[]) encryptedR1bis.getObject(this.decryptWithWSPrivateKey);
			if(!this.compare(decryptedRandom1bis,random1)) {
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
		this.decryptWithASSharedKey = this.getCipherOfSharedKey(this.sharedWithASKey,DECRYPT);
		//end of STEP 4
		System.out.println("step4 ok; handshake successful");
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
		System.out.println("comparaison:"+res);
		return res;
	}

	/**
	 * initialise the cipher used to encrypt/decrypt messages, using the shared AES key
	 * @param sharedKey key to decipher
	 * @param mode ENCRYPT or DECRYPT according to the use
	 * @return the Cipher needed to en/de-crypt a sealed object; null if an error occured
	 */
	protected Cipher getCipherOfSharedKey(Key sharedKey, int mode) {
		Cipher res = null;
		try {
//			this.decryptWithASSharedKey = Cipher.getInstance("AES/CBC/PKCS5Padding");
//			this.decryptWithASSharedKey.init(Cipher.DECRYPT_MODE, this.sharedWithASKey,new IvParameterSpec(new byte[16]));
			res = Cipher.getInstance("AES/CBC/PKCS5Padding");
			int opmode;
			if(mode==ENCRYPT)
				opmode = Cipher.ENCRYPT_MODE;
			else if(mode==DECRYPT)
				opmode = Cipher.DECRYPT_MODE;
			else
				opmode = -1;
			
			res.init(opmode, sharedKey,new IvParameterSpec(new byte[16]));
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println("WebThread: error AES decryption:"+e.getMessage());
		} catch (NoSuchPaddingException e) {
			System.out.println("WebThread: error AES decryption:"+e.getMessage());		
		} catch (InvalidKeyException e) {
			System.out.println("WebThread: error AES decryption:"+e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("WebThread: error AES decryption:"+e.getMessage());
		}
		return res;
	}
	
	/** 
	 * Init input/output stream (object) for the AS connection
	 */
	private void initASObjectIOStream() {
//		if(ASSocketOOS == null) {
		ASSocketOOS = null;
			try {
				this.ASSocketOOS = new ObjectOutputStream(this.ASsocket.getOutputStream());
				this.ASSocketOOS.flush();
				System.out.println("WS:initialised ASSocketOOS ok");
			} catch (IOException e) {
				e.printStackTrace();
			}
//		}
			ASSocketOIS = null;
//		if(ASSocketOIS == null) {
//			System.out.println("In between");
			try {
				this.ASSocketOIS = new ObjectInputStream(this.ASsocket.getInputStream());
				System.out.println("WS:initialised ASSocketOIS ok");
			} catch (IOException e) {
				System.out.println("CAUGHT A BULLET");
				e.printStackTrace();
			}
//		}
//		return clientOOS;
	}

	/**
	 * random nonce generator
	 * @return
	 */
	private static byte[] generateNonce() { //TODO change long -> byte[16]
//		Random generator = new Random();
//		Long result = generator.nextLong();
//		while(nonces.contains(result)) {
//			result = generator.nextLong();
//			System.out.println("WebServer : SHOULD NOT BE HERE... ELSE, CRAPPY RANDOM GENERATOR");
		//		}
		//		System.out.println("WebServer : Nonce generated="+result.longValue());
		byte[] res = new byte[16];
		Random rand=null;
		try {
			rand = SecureRandom.getInstance("SHA1PRNG");
			rand.nextBytes(res);
			while(nonces.contains(res)) {
				rand.nextBytes(res);
				System.out.println("WS: SHOULD NOT BE HERE"); //DEBUG purpose
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
//		System.out.print("WebServer : Nonce generated=");
//		for(int i=0;i<16;i++)
//			System.out.printf("0x%02X ", res[i]);
		return res;
//		return result.longValue();
	}

	/**
	 * recoit de l'AS les infos du client qui veut se connecter :
	 * - ID du client
	 * - la cle partagee entre WS et Client
	 * - la cryptoperiode de la cle en secondes
	 * 
	 * TODO N.B. En pratique, il serait peut-etre plus utile de garder la liste sur disque dur?
	 */
	private void addNewClientInfo(int ID, Key sharedKey, int period) {
		if(! this.clientIDList.contains(ID)) {
			System.out.println("WS: adding new client: ID="+ID+",cryptoperiod="+period);
			this.clientIDList.add(ID);
			this.clientKeyList.add(sharedKey);
			long expTime;
			if(period>0)
				expTime = System.currentTimeMillis() + period*1000; //1000 for ms
			else //if error on cryptoperiod :
				expTime = System.currentTimeMillis(); 
			this.clientPeriodList.add(expTime);
		} else
			System.out.println("WS: new client already exists");
	}

	/**
	 * boucle principale du serveur :
	 * - cree un thread pour ajouter les infos venant de l'AS
	 * - thread principal : gere le client
	 */
	private void mainLoop() {//TODO uncomment
		new Thread(this).start(); //lance le thread AS <-> WS qui gere l'ajout de nouveaux clients
		//recoit une connexion et la traite
		while(true) {
			Socket clientSocket;
			ObjectOutputStream out;
			ObjectInputStream in;
			try {
				System.out.println("WS: waiting for new client...");
				clientSocket = this.serverSocket.accept();
				System.out.println("WS: new client connected");				
				out = new ObjectOutputStream(clientSocket.getOutputStream());
				in = new ObjectInputStream(clientSocket.getInputStream());
				
				//recupere le message depuis l'input
				ArrayList<?> message = (ArrayList<?>) in.readObject();
				//recupere l'ID du client et verifie si correct et si cryptoperiode valide
				int clientID = (Integer) message.get(0);
				System.out.println("Client ID : "+clientID);
				boolean verif = this.verifyClient(clientID);
				if(verif) { //si ok, dechiffre la requete et la traite
					System.out.println("Verification succeeded, answering");
					int requestType = (Integer) this.decipherRequest( (SealedObject) message.get(1), clientID);
					String requestMsg = "";
					if(message.size()==3) {
						requestMsg = (String) this.decipherRequest((SealedObject) message.get(2), clientID);
						System.out.println("WS: Client request HAS msg"); //TODO TEST ONLY
					}
					this.answerClientRequest(requestType,requestMsg,clientID,out);
				} else
					System.out.println("Verification failed"); //DEBUG
				//si non ou si requete traitee, ferme la connexion
				out.close();
				in.close();
				clientSocket.close();
				System.out.println("WS: connection with the client closed");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * recupere l'ID du client et verifie si correct et si sa cryptoperiode est valide
	 * @param clientID ID a verifier
	 * @return true si client correct, false sinon
	 */
	private boolean verifyClient(int clientID) {
		int index = clientIDList.indexOf(clientID);
		if(index<0) {
			System.out.println("WS: client non trouve dans la liste");
			return false; 
		}
		long period = this.clientPeriodList.get(index) - System.currentTimeMillis();
		if(period>0) {
			System.out.println("Cryptoperiod still valid:"+period+"(ms)");
		} else {
			System.out.println("Cryptoperiod not valid anymore:"+period+"(ms)");
			return false;
		}
		return false;
	}

	/**
	 * dechiffre la requete du client en utilisant la clef correspondante dans la liste des clefs
	 * @param encryptedRequest requete a dechiffrer
	 * @param clientID ID pour recuperer la clef de dechiffrement
	 * @return l'ID de la requete, -1 en cas d'erreur
	 */
	private Object decipherRequest(SealedObject encryptedRequest, int clientID) {
		Key decryptKey = this.getClientKey(clientID);
		Cipher ciph = this.getCipherOfSharedKey(decryptKey,DECRYPT); //get the decipher
		Object request = null;
		try {
			request = encryptedRequest.getObject(ciph);
		} catch (IllegalBlockSizeException e) {
			System.out.println("WS: decipherRequest failed:");
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.out.println("WS: decipherRequest failed:");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("WS: decipherRequest failed:");
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			System.out.println("WS: decipherRequest failed:");
			e.printStackTrace();
		}
		return request;
	}
	
	protected Key getClientKey(int clientID) {
		int index = this.clientIDList.indexOf(clientID);
		if(index>=0)
			return this.clientKeyList.get(index);
		else 
			return null;
	}
	
	/**
	 * recoit la requete du client et repond avec le service demande
	 * @param request ID de la requete
	 */
	protected abstract void answerClientRequest(int requestType, String reqMsg, int clientID, ObjectOutputStream out);

	/**
	 * Thread qui s'occupe de rajouter les infos des nouveaux clients, recues de l'AS
	 */
	@Override
	public void run() {
		System.out.println("Starting thread AS<->WS");
		
//		//init input stream
//		ObjectInputStream receiveFromAS = null;
//		try {
//			receiveFromAS = new ObjectInputStream(ASsocket.getInputStream());
//		} catch (IOException e) {
//			System.out.println("WebService Thread: error Getting input stream:"+e.getMessage());
//		}
		
		//init variables
		Object received;
		boolean exit = false;
		int idFromAS;
		SealedObject encryptedClientID, encryptedClientSharedKey, encryptedCryptoperiod;
		int clientID, cryptoperiod;
		Key clientSharedKey;
		//while connection with AS
		while(!exit) {
//			System.out.println("WebThread while loop");
			try {
				//read message
//				received=receiveFromAS.readObject();
				System.out.println("Thread waiting for incoming msg from AS");
				received = this.ASSocketOIS.readObject();
				System.out.println("Thread received new msg from AS");
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
				} else {
					System.out.println("WebThread: error wrong AS_ID !");
					exit = true;
				}
			} catch (IOException e) {
				System.out.println("WebThread IO error:"+e.getMessage());
//				e.printStackTrace();
				exit = true;
			} catch (ClassNotFoundException e) {
				System.out.println("WebThread Class not found:"+e.getMessage());
				exit = true;
			} catch (IllegalBlockSizeException e) {
				System.out.println("WebThread illegal block size error:"+e.getMessage());
				exit = true;
			} catch (BadPaddingException e) {
				System.out.println("WebThread bad padding error:"+e.getMessage());
				exit = true;
			}
		}
		
		closeASSocket();
//		try {
//			receiveFromAS.close();
//			System.out.println("WebThread : AS socket closed");
//		} catch (IOException e) {
//			System.out.println("WebThread : error closing AS socket");
//			e.printStackTrace();
//		}
	}
	
	private void closeASSocket() {
		try {
			this.ASSocketOIS.close();
			this.ASSocketOOS.close();
			this.ASsocket.close();
			System.out.println("WebService : AS socket closed");
		} catch (IOException e) {
			System.out.println("WebService: error closing AS socket");
			e.printStackTrace();
		}
	}
}
