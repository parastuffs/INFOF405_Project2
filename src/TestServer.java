import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.net.ServerSocketFactory;


public class TestServer implements Runnable{
	
	public TestServer() {
		
	}

	@Override
	public void run() {
        ServerSocketFactory serversocketfactory = ServerSocketFactory.getDefault();
        ServerSocket serverSocket=null;
		try {
			serverSocket = serversocketfactory.createServerSocket(42000);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		//while(true) {
			try {
	            System.out.println("Server ready and waiting for a client");
	            Socket socket = serverSocket.accept();
	            System.out.println("nouveau client connecté: "+socket.getInetAddress().toString());
	            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
	            
	            ArrayList<Object> distantObjects = new ArrayList<Object>();
	            distantObjects = (ArrayList<Object>) ois.readObject();
	            
	            int clientID = (int)distantObjects.get(0);
	            System.out.println("client ID: "+clientID);
	            
	            int wsID = (int)distantObjects.get(1);
	            System.out.println("Web Service ID: "+wsID);
	            
	            //TODO the private key is transmitted for testing purpose only
	            PrivateKey privKey = (PrivateKey)distantObjects.get(2);
	            //System.out.println("private key on the server: "+privKey);
	            
	            SealedObject sealedClientID = (SealedObject)distantObjects.get(3);
	            String algo = sealedClientID.getAlgorithm();
	            Cipher ciph = Cipher.getInstance(algo);
	            ciph.init(Cipher.DECRYPT_MODE, privKey);
	            int decryptedClientID = (int)sealedClientID.getObject(ciph);
	            System.out.println("Decrypted client ID: "+decryptedClientID);
	            
	            
	            
//	            InputStream inputstream = socket.getInputStream();
//	            InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
//	            BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
	            
	            
	            socket.close();
	            serverSocket.close();
	            
	        } catch (Exception exception) {
	            exception.printStackTrace();
	        }
		//}
		
	}

}
