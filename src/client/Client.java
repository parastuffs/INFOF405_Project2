package client;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.ListIterator;
import java.util.Random;
import java.util.Scanner;
import java.util.Timer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class Client {
	
	private Socket sockAS;
	private Socket sockWS1;
	private Socket sockWS2;
	private final int PORT_AS = 42000;
	private final int PORT_WS1 = 2013;
	private final int PORT_WS2 = 2014;
	private final int WS1_PRINT = 0;
	private final int WS1_WRITE = 1;
	private final int WS2_PRINT = 0;
	private final int WS2_WRITE = 1;
	private byte[] r3;
	private byte[] r4;
	private final int CLIENT_ID = 10;
	private final int AS_ID = 0;
	private final int WS1_ID = 1;
	private final int WS2_ID = 2;
	private final String PRIVATEKEYFILE = "certs/key.CL1.private.pem";
	private final String PUBLICKEYFILE_AS = "certs/key.AS.pub.pem";
	
	private PrivateKey clientPrivateKey;
	private PublicKey ASPublicKey;
	//private SecretKeySpec sharedKeyWS1;
	//private SecretKey sharedKeyWS1;
	private Key sharedKeyWS1;
	private int cryptoperiodWS1;
	private int cryptoperiodWS2;
	private Key sharedKeyWS2;
	
	public Client() {

		System.out.println("Loading the keys...");
		
		this.clientPrivateKey = loadPrivateKey(this.PRIVATEKEYFILE, "RSA");
		this.ASPublicKey = loadPublicKey(this.PUBLICKEYFILE_AS, "RSA");
		
		System.out.println("Key loaded.");
	
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
	
	/**
	 * Requests access to the webservice at the Authorisation Server.
	 * There are three passes:
	 * 				<ul><li>Client announces himself to AS.</li>
	 * 					<li>AS responds with a challenge.</li>
	 * 					<li>Client sends the challenge back, non-ciphered.</li></ul>
	 * 
	 * @throws UnknownHostException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws ClassNotFoundException
	 */
	@SuppressWarnings("unchecked")
	public boolean requestWSAccess(int WSid) throws UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, ClassNotFoundException {
		this.sockAS = new Socket("localhost", PORT_AS);//Connection to AS
		
		//
		//First announces itself to the AS
		//
		this.r3 = new byte[16];
		Random rand = SecureRandom.getInstance("SHA1PRNG");
		rand.nextBytes(r3);
		
		//Encryption
		Cipher ciph = Cipher.getInstance("RSA");//RSA encryption
		ciph.init(Cipher.ENCRYPT_MODE, this.ASPublicKey);
		SealedObject encryptedClientID = new SealedObject(CLIENT_ID, ciph);
		SealedObject encryptedNonce = new SealedObject(this.r3, ciph);
		SealedObject encryptedWSID = new SealedObject(WSid, ciph);

		/**
		 * Array of all the elements to be sent to the distant server:
		 * client ID, WS ID, E_AS(client ID), E_AS(r3)
		 */
		ArrayList<Object> message = new ArrayList<Object>();//List of the objects to send to AS
		message.add(CLIENT_ID);//0
		message.add(WSid);//1
		message.add(encryptedClientID);//2
		message.add(encryptedWSID);//3
		message.add(encryptedNonce);//4

		System.out.println("Sending to server");
		
		ObjectOutputStream outAS = new ObjectOutputStream(this.sockAS.getOutputStream());
		outAS.writeObject(message);
		outAS.flush();
		
		//
		//Second, awaits the answer from the AS
		//
        ObjectInputStream ois = new ObjectInputStream(this.sockAS.getInputStream());
        ArrayList<Object> distantObjects = new ArrayList<Object>();
        distantObjects = (ArrayList<Object>)ois.readObject();
        int idASchallenge = (int)RSADecipher(distantObjects.get(0));
        int idWSchallenge = (int)RSADecipher(distantObjects.get(1));
        byte[] r3Challenge = new byte[16];
        r3Challenge = (byte[])RSADecipher(distantObjects.get(2)); 
        this.r4 = new byte[16];
        this.r4 = (byte[])RSADecipher(distantObjects.get(3));//Decrypt the challenge
        
        
        
        
        
        //Time to check that everything sent by AS is OK:
        if(idASchallenge == this.AS_ID && idWSchallenge == WSid && Arrays.equals(r3Challenge,this.r3)) {
        	
        	//
        	//Third, sends the challenge, clear, to AS.
        	//
        	System.out.println("Everything is fine so far, proceeding to step 3: sending back the challenge r4.");
        	outAS.writeObject(this.r4);
        	outAS.flush();
        	
        	//
        	//Fourth, AS sends the symmetric key to dialog with WS
        	//
        	ArrayList<Object> answer = new ArrayList<Object>();
        	answer = (ArrayList<Object>)ois.readObject();
        	System.out.println("Client just received the key");
        	
        	//Creation of the AES key
        	String algo = this.clientPrivateKey.getAlgorithm();
    		Cipher ciphBis = Cipher.getInstance(algo);
    		ciphBis.init(Cipher.DECRYPT_MODE, this.clientPrivateKey);
    		SealedObject encryptedAESKey = (SealedObject)answer.get(0);
			byte[] AESKey = new byte[16];
    		AESKey = (byte[])RSADecipher(encryptedAESKey);
    		
    		if(WSid == this.WS1_ID) {
	    		this.sharedKeyWS1 = new SecretKeySpec(AESKey, 0, 16, "AES");    		
	    		
	    		this.cryptoperiodWS1 = (int)RSADecipher(answer.get(1));
	    		
	    		//Program the suicide of the key
	    		TimerKey  timer = new TimerKey(this);
	    		Timer t = new Timer();
	    		t.schedule(timer, cryptoperiodWS1*1000);
    		}
    		else if(WSid == this.WS2_ID) {
    			this.sharedKeyWS2 = new SecretKeySpec(AESKey, 0, 16, "AES");    		
    		
	    		this.cryptoperiodWS2 = (int)RSADecipher(answer.get(1));
	    		
	    		//Program the suicide of the key
	    		TimerKey  timer = new TimerKey(this);
	    		Timer t = new Timer();
	    		t.schedule(timer, this.cryptoperiodWS2*1000);
    		}
    		
        	r3Challenge = (byte[])RSADecipher(answer.get(2));
        	
        	//closing the IO stream :
        	outAS.close();
        	ois.close();
        	
        	if(Arrays.equals(r3Challenge,this.r3)) {
        		closeConnectionAS();
        		System.out.println("Key reception successful. The client can know talk to WS");
        		//OK; open communication with WS1.
        		return true;
        	}
        	else {
        		//Challenge from AS not accepted.
        		closeConnectionAS();
        		return false;
        	}
        	
        }
        else {
        	System.out.println("Something went wrong during the verification:");            	
        	System.out.println("idASchallenge="+idASchallenge+", expecting "+this.AS_ID);
        	System.out.println("idWSchallenge="+idWSchallenge+", expecting "+WSid);
        	System.out.println("r3Challenge="+new String(r3Challenge,"UTF-8")+", expecting "+new String(this.r3,"UTF-8"));
        	closeConnectionAS();
        	return false;
        }
		
	}
	
	@SuppressWarnings("unchecked")
	private void printBlackBoard() {
		
		
		try {

			if(this.sharedKeyWS1 == null) {
				requestWSAccess(this.WS1_ID);
			}
			
			this.sockWS1 = new Socket("localhost", PORT_WS1);
			ArrayList<Object> request = new ArrayList<Object>();
			
			SealedObject encryptedRequestType = AESCipher(WS1_PRINT);			
			
			//Adds the elements to the list
			request.add(CLIENT_ID);
			request.add(encryptedRequestType);

			//Sends the object
			ObjectOutputStream outWS = new ObjectOutputStream(sockWS1.getOutputStream());
			outWS.writeObject(request);
			outWS.flush();
			
			//Receives the messages
			ObjectInputStream ois = new ObjectInputStream(this.sockAS.getInputStream());
	        ArrayList<String> blackBoardMes = new ArrayList<String>();
	        blackBoardMes = (ArrayList<String>)AESDecipher(ois.readObject());
			
			this.sockWS1.close();
			
			
			ListIterator<String> li = blackBoardMes.listIterator();
			System.out.println("Your blackboard:\n------------");
			while(li.hasNext()) {
				System.out.println(li.next()+"------------");
			}
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | ClassNotFoundException
				| IOException e) {
			e.printStackTrace();
		}
		
		
	}
	
	private void writeBlackBoard() {
		
		System.out.println("Alright. Please type hereunder the message to write on your black board:");
		Scanner sc = new Scanner(System.in);
		String message = "";
		message += sc.nextLine();
		sc.close();
		try {

			if(this.sharedKeyWS1 == null) {
				requestWSAccess(this.WS1_ID);
			}
	
			this.sockWS1 = new Socket("localhost", PORT_WS1);
			ArrayList<Object> request = new ArrayList<Object>();
			
			//Encryption
			SealedObject encryptedRequestType = AESCipher(WS1_WRITE);	
			SealedObject encryptedMessage = AESCipher(message);
			
			//Adds the elements to the list
			request.add(CLIENT_ID);//0
			request.add(encryptedRequestType);//1
			request.add(encryptedMessage);//2

			//Sends the object
			ObjectOutputStream outWS = new ObjectOutputStream(sockWS1.getOutputStream());
			outWS.writeObject(request);
			outWS.flush();
			System.out.println("Message sent. Awaiting the web service answer...");
			
			//Receives the messages
			ObjectInputStream ois = new ObjectInputStream(this.sockWS1.getInputStream());
	        if((boolean)AESDecipher(ois.readObject())) {
	        	System.out.println("Writing successful.");
	        }
	        else {
	        	System.out.println("Writing failed.");
	        }
			
			this.sockWS1.close();
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | ClassNotFoundException
				| IOException e) {
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("unchecked")
	private void printPasswd() {
		try {

			if(this.sharedKeyWS2 == null) {
				requestWSAccess(this.WS2_ID);
			}
			
			this.sockWS2 = new Socket("localhost", this.PORT_WS2);
			ArrayList<Object> request = new ArrayList<Object>();

			SealedObject encryptedRequestType = AESCipher(WS2_PRINT);			
			
			//Adds the elements to the list
			request.add(CLIENT_ID);
			request.add(encryptedRequestType);

			//Sends the object
			ObjectOutputStream outWS = new ObjectOutputStream(sockWS2.getOutputStream());
			outWS.writeObject(request);
			outWS.flush();
			
			//Receives the messages
			ObjectInputStream ois = new ObjectInputStream(this.sockAS.getInputStream());
	        ArrayList<String> passMes = new ArrayList<String>();
	        passMes = (ArrayList<String>)AESDecipher(ois.readObject());
			
			this.sockWS2.close();
			
			
			ListIterator<String> li = passMes.listIterator();
			System.out.println("Your Passwords:\n------------");
			while(li.hasNext()) {
				System.out.println(li.next()+"------------");
			}
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | ClassNotFoundException
				| IOException e) {
			e.printStackTrace();
		}
	}
	
	private void addPasswd() {
		System.out.println("Alright. Please type hereunder the password to store:");
		Scanner sc = new Scanner(System.in);
		String message = "";
		message += sc.nextLine();
		sc.close();
		try {

			if(this.sharedKeyWS2 == null) {
				requestWSAccess(this.WS2_ID);
			}
	
			this.sockWS1 = new Socket("localhost", PORT_WS2);
			ArrayList<Object> request = new ArrayList<Object>();
			
			//Encryption
			SealedObject encryptedRequestType = AESCipher(WS2_WRITE);	
			SealedObject encryptedMessage = AESCipher(message);
			
			//Adds the elements to the list
			request.add(CLIENT_ID);//0
			request.add(encryptedRequestType);//1
			request.add(encryptedMessage);//2

			//Sends the object
			ObjectOutputStream outWS = new ObjectOutputStream(sockWS2.getOutputStream());
			outWS.writeObject(request);
			outWS.flush();
			System.out.println("Message sent. Awaiting the web service answer...");
			
			//Receives the messages
			ObjectInputStream ois = new ObjectInputStream(this.sockWS2.getInputStream());
	        if((boolean)AESDecipher(ois.readObject())) {
	        	System.out.println("Writing successful.");
	        }
	        else {
	        	System.out.println("Writing failed.");
	        }
			
			this.sockWS2.close();
			
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | ClassNotFoundException
				| IOException e) {
			e.printStackTrace();
		}
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
        
        String algo = this.clientPrivateKey.getAlgorithm();
		try {
			Cipher ciph = Cipher.getInstance(algo);
			ciph.init(Cipher.DECRYPT_MODE, this.clientPrivateKey);
			return (Object)((SealedObject) ciphered).getObject(ciph);
		} catch (ClassNotFoundException | IllegalBlockSizeException
				| BadPaddingException | IOException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private Object AESDecipher(Object ciphered) {
        try {
            String algo = ((SealedObject) ciphered).getAlgorithm();//Get the algorithm
            Cipher ciph = Cipher.getInstance(algo);//Get the cipher
            ciph.init(Cipher.DECRYPT_MODE, this.sharedKeyWS1, new IvParameterSpec(new byte[16]));//Decrypt
			return ((SealedObject)ciphered).getObject(ciph);
		} catch (ClassNotFoundException | IllegalBlockSizeException
				| BadPaddingException | IOException | InvalidKeyException
				| InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private SealedObject AESCipher(Serializable toBeCiphered) {
		try {
			Cipher ciph = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ciph.init(Cipher.ENCRYPT_MODE, this.sharedKeyWS1, new IvParameterSpec(new byte[16]));
			return new SealedObject(toBeCiphered, ciph);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException 
				| NoSuchAlgorithmException | NoSuchPaddingException 
				| IllegalBlockSizeException | IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Destroy the shared AES key.
	 */
	public void destroyAESKeyWS1() {
		this.sharedKeyWS1 = null;
	}
	
	/**
	 * Closes the connection with AS.
	 */
	private void closeConnectionAS() {
		try {
			this.sockAS.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	
	public static void main(String[] args) {

		Client c = new Client();
		boolean running = true;
		Scanner sc = new Scanner(System.in);
		while(running) {
			System.out.println("Hello dear sir, what do you want to do on this beatiful day?");
			System.out.println("1 - Display everything on your blackboard");
			System.out.println("2 - Add a new message on your blackboard");
			System.out.println("3 - Display all your passwords");
			System.out.println("4 - Add a new password");
			System.out.println("5 - Leave");
			int uChoice = sc.nextInt();
			if( uChoice == 1) {
				c.printBlackBoard();
			}
			else if(uChoice == 2) {
				c.writeBlackBoard();
			}
			else if(uChoice == 3) {
				c.printPasswd();
			}
			else if(uChoice == 4) {
				c.addPasswd();
			}
			else if(uChoice == 5) {
				running = false;
			}
		}
		sc.close();
	}

}
