import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;


public class TestAESServer implements Runnable{
	
	private final String key = "Ivenoideawhatodo";
	
	public TestAESServer() {
		
	}

	@Override
	public void run() {
		ServerSocketFactory serversocketfactory = ServerSocketFactory.getDefault();
        ServerSocket serverSocket=null;
		try {
			serverSocket = serversocketfactory.createServerSocket(2013);
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
            System.out.println("Server AES TESTING ready and waiting for a client");
            Socket socket = serverSocket.accept();
            System.out.println("nouveau client connecté: "+socket.getInetAddress().toString());
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            
            SealedObject so = (SealedObject) ois.readObject();
            
            byte[] raw = key.getBytes();
            SecretKeySpec sks = new SecretKeySpec(raw, "AES");
            String algo = so.getAlgorithm();//Get the algorithm
            Cipher ciph = Cipher.getInstance(algo);//Get the cipher
            ciph.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(new byte[16]));//Decrypt
            String decipheredMes = (String)so.getObject(ciph);
            System.out.println("Decrypted message: "+decipheredMes);
            
            socket.close();
            serverSocket.close();
            
        } catch (Exception exception) {
            exception.printStackTrace();
        }
	}

}
