package client;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.ListIterator;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;


public class Client {
	
	private Socket sockAS;
	private Socket sockWS1;
	private final int PORT_AS = 42000;
	private final int PORT_WS1 = 2013;
	private final int WS1_PRINT = 0;
	private final int WS1_WRITE = 1;
	private byte[] r1;
	private byte[] r3;
	private byte[] r4;
	private final int CLIENT_ID = 10;
	private final int AS_ID = 0;
	private final int WS1_ID = 1;
	private final int WS2_ID = 2;
	
	private PrivateKey clientPrivateKey;
	private PublicKey clientPublicKey;
	private PublicKey ASPublicKey;
	private SecretKeySpec sharedKeyWS1;
	private int cryptoperiodWS1;
	
	public Client() {

		
		//For testing purpose only ####
		try {
			generateKeys();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		//####
	
	}
	
	/**
	 * Method loading the public and private keys from the .pem files.
	 * TODO to populate
	 * @param filename .pem file containing the keys
	 */
	private void loadPrivateKey(String filename) {
		File f = new File(filename);
		FileInputStream fis;
		try {
			fis = new FileInputStream(f);
			DataInputStream dis = new DataInputStream(fis);
			
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Requests access to the blackboard at the Authorisation Server.
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
	public boolean requestAccessBlackBoard() throws UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, ClassNotFoundException {
		this.sockAS = new Socket("localhost", PORT_AS);//Connection to AS
		
		//
		//First announces itself to the AS
		//
		this.r3 = new byte[16];
		Random rand = SecureRandom.getInstance("SHA1PRNG");
		rand.nextBytes(r3);
		
		Cipher ciph = Cipher.getInstance("RSA");//RSA encryption
		ciph.init(Cipher.ENCRYPT_MODE, this.clientPublicKey);//TODO WARNING/!\ we currently encrypt the message with the client public key.
		
		SealedObject encryptedClientID = new SealedObject(CLIENT_ID, ciph);
		SealedObject encryptedNonce = new SealedObject(this.r3, ciph);

		/**
		 * Array of all the elements to be sent to the distant server:
		 * client ID, WS ID, E_AS(client ID), E_AS(r3)
		 */
		ArrayList<Object> message = new ArrayList<Object>();//List of the objects to send to AS
		message.add(CLIENT_ID);
		message.add(AS_ID);
		//TODO adding the private key to the list is temporary, for testing purpose only
		//message.add(this.clientPrivateKey);
		message.add(encryptedClientID);
		message.add(encryptedNonce);

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
        this.r4 = (byte[])RSADecipher(distantObjects.get(3));
        
        //Time to check that everything sent by AS is OK:
        if(idASchallenge == this.AS_ID && idWSchallenge == this.WS1_ID && r3Challenge == this.r3) {
        	
        	//
        	//Third, sends the challenge, clear, to AS.
        	//
        	outAS.writeObject(this.r4);
        	
        	//
        	//Fourth, AS sends the symmetric key to dialog with WS
        	//
        	distantObjects = (ArrayList<Object>)ois.readObject();
        	this.sharedKeyWS1 = (SecretKeySpec)RSADecipher(distantObjects.get(0));
        	this.cryptoperiodWS1 = (int)RSADecipher(distantObjects.get(1));
        	r3Challenge = (byte[])RSADecipher(distantObjects.get(2));
        	
        	if(r3Challenge == this.r3) {
        		closeConnectionAS();
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
        	closeConnectionAS();
        	return false;
        }
		
	}
	
	public void testAESConnection() throws UnknownHostException, IOException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.sockWS1 = new Socket("localhost", PORT_WS1);//Connection to WS
		
		
		String key = "Ivenoideawhatodo";
		byte[] raw = key.getBytes();
		SecretKeySpec sks = new SecretKeySpec(raw, "AES");
		Cipher ciph = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ciph.init(Cipher.ENCRYPT_MODE, sks, new IvParameterSpec(new byte[16]));
		
		SealedObject encryptedMessage = new SealedObject("Hello, this is dog.", ciph);
		
		System.out.println("Sending to server");
		
		ObjectOutputStream outWS = new ObjectOutputStream(sockWS1.getOutputStream());
		outWS.writeObject(encryptedMessage);
		outWS.flush();
		
		sockAS.close();
		
	}
	
	
	private void generateKeys() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair kp = kpg.generateKeyPair();
		PublicKey pubKey = kp.getPublic();
		PrivateKey privKey = kp.getPrivate();
		
		this.clientPublicKey = pubKey;
		this.clientPrivateKey = privKey;
		
		//System.out.println("Client Private key: "+privKey);
		//System.out.println("Client Public key: "+pubKey);
	}
	
	private void printBlackBoard() {
		
		
		try {

			if(requestAccessBlackBoard()) {
			
				this.sockWS1 = new Socket("localhost", PORT_WS1);
				ArrayList<Object> request = new ArrayList<Object>();
				
				//
				//AES construction
				//
				String key = "Ivenoideawhatodo";
				byte[] raw = key.getBytes();
				SecretKeySpec sks = new SecretKeySpec(raw, "AES");
				Cipher ciph = Cipher.getInstance("AES/CBC/PKCS5Padding");
				ciph.init(Cipher.ENCRYPT_MODE, sks, new IvParameterSpec(new byte[16]));
	
				SealedObject encryptedRequestType = new SealedObject(WS1_PRINT, ciph);			
				
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
		        blackBoardMes = (ArrayList<String>)AESDecipher(ois.readObject(), key);
				
				this.sockWS1.close();
				
				
				ListIterator<String> li = blackBoardMes.listIterator();
				System.out.println("Your blackboard:\n------------");
				while(li.hasNext()) {
					System.out.println(li.next()+"------------");
				}
				
				
			}
			else {
				//Connection refused.
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | ClassNotFoundException
				| IOException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		
		
	}
	
	private void writeBlackBoard() {
		
		System.out.println("Alright. Please type hereunder the message to write on your black board:");
		Scanner sc = new Scanner(System.in);
		String message = "Lamasticot";
		while(sc.hasNextLine()) {
			message += sc.nextLine();
		}
		sc.close();
		
		try {

			if(requestAccessBlackBoard()) {
			
				this.sockWS1 = new Socket("localhost", PORT_WS1);
				ArrayList<Object> request = new ArrayList<Object>();
				
				//
				//AES construction
				//
				String key = "Ivenoideawhatodo";
				byte[] raw = key.getBytes();
				SecretKeySpec sks = new SecretKeySpec(raw, "AES");
				Cipher ciph = Cipher.getInstance("AES/CBC/PKCS5Padding");
				ciph.init(Cipher.ENCRYPT_MODE, sks, new IvParameterSpec(new byte[16]));
	
				SealedObject encryptedRequestType = new SealedObject(WS1_WRITE, ciph);	
				SealedObject encryptedMessage = new SealedObject(message, ciph);
				
				//Adds the elements to the list
				request.add(CLIENT_ID);
				request.add(encryptedRequestType);
				request.add(encryptedMessage);

				//Sends the object
				ObjectOutputStream outWS = new ObjectOutputStream(sockWS1.getOutputStream());
				outWS.writeObject(request);
				outWS.flush();
				
				//Receives the messages
				ObjectInputStream ois = new ObjectInputStream(this.sockAS.getInputStream());
		        if((boolean)AESDecipher(ois.readObject(), key)) {
		        	System.out.println("Wrting successful.");
		        }
		        else {
		        	System.out.println("Wrting failed.");
		        }
				
				this.sockWS1.close();
				
				
			}
			else {
				//Connection refused.
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | ClassNotFoundException
				| IOException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}
	
	private void printPasswd() {
		
	}
	
	private void addPasswd() {
		
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
	
	private Object AESDecipher(Object ciphered, String key) {
        try {
        	byte[] raw = key.getBytes();
            SecretKeySpec sks = new SecretKeySpec(raw, "AES");
            String algo = ((SealedObject) ciphered).getAlgorithm();//Get the algorithm
            Cipher ciph = Cipher.getInstance(algo);//Get the cipher
            ciph.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(new byte[16]));//Decrypt
			return ((SealedObject)ciphered).getObject(ciph);
		} catch (ClassNotFoundException | IllegalBlockSizeException
				| BadPaddingException | IOException | InvalidKeyException
				| InvalidAlgorithmParameterException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Destroy the shared AES key.
	 */
	public void destroyAESKey() {
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
		
		System.out.println("Hello dear sir, what do you want to do on this beatiful day?");
		System.out.println("1 - Display everything on your blackboard");
		System.out.println("2 - Add a new message on your blackboard");
		System.out.println("3 - Display all your passwords");
		System.out.println("4 - Add a new password");
		Scanner sc = new Scanner(System.in);
		int uChoice = sc.nextInt();
		sc.close();
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
		
		//Thread t = new Thread(new TestServer());
		//t.start();
		//Thread t1 = new Thread(new TestAESServer());
		//t1.start();
		
		try {
			c.requestAccessBlackBoard();
			//c.testAESConnection();
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | IOException 
				| ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

}
