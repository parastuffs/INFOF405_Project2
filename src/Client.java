import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import java.util.Random;

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
	private byte[] r1;
	private byte[] r3;
	private final int CLIENT_ID = 10;
	private final int AS_ID = 0;
	private final int WS1_ID = 1;
	private final int WS2_ID = 2;
	
	private PrivateKey clientPrivateKey;
	private PublicKey clientPublicKey;
	private PublicKey ASPublicKey;
	
	public Client() {

		
		//For testing purpose only ####
		try {
			generateKeys();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		//####
	
	}
	
	private void loadPrivateKey(String filename) {
		File f = new File(filename);
		
	}
	
	public void requestAccessBlackBoard() throws UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
		this.sockAS = new Socket("localhost", PORT_AS);//Connection to AS
		this.r3 = new byte[16];
		Random rand = SecureRandom.getInstance("SHA1PRNG");
		rand.nextBytes(r3);
		
		/**
		 * Array of all the elements to be sent to the distant server:
		 * client ID, WS ID, E_AS(client ID), E_AS(r3)
		 */
		ArrayList<Object> message = new ArrayList<Object>();//List of the objects to send to AS
		//TODO remove dead code
		//ArrayList<Object> toBeCrypted = new ArrayList<Object>();//List of object to encrypt with RSA
		message.add(CLIENT_ID);
		message.add(AS_ID);
		
		Cipher ciph = Cipher.getInstance("RSA");//RSA encryption
		ciph.init(Cipher.ENCRYPT_MODE, this.clientPublicKey);//TODO WARNING/!\ we currently encrypt the message with the client public key.
		
		//TODO adding the private key to the list is temporary, for testing purpose only
		message.add(this.clientPrivateKey);
		
		SealedObject encryptedClientID = new SealedObject(CLIENT_ID, ciph);
		SealedObject encryptedNonce = new SealedObject(this.r3, ciph);
		message.add(encryptedClientID);
		message.add(encryptedNonce);

		System.out.println("Sending to server");
		
		ObjectOutputStream outAS = new ObjectOutputStream(sockAS.getOutputStream());
		outAS.writeObject(message);
		outAS.flush();
		
		sockAS.close();
		
		System.out.println("Vers l'infini et au-dela !");
		
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
	
	
	
	
	public static void main(String[] args) {
		
		Thread t = new Thread(new TestServer());
		t.start();
		Thread t1 = new Thread(new TestAESServer());
		t1.start();
		
		try {
			Client c = new Client();
			c.requestAccessBlackBoard();
			c.testAESConnection();
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | IOException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}

}
