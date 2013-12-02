package authorisationServer;

import java.io.IOException;
import java.net.ServerSocket;

import javax.net.ServerSocketFactory;

public class ASConnectionHandler implements Runnable {

	private ServerSocket serverSocket;
	private final int PORT = 42000;
	
	public ASConnectionHandler() {
		//initiate Socket
		ServerSocketFactory servFactory = ServerSocketFactory.getDefault();
		try {
			serverSocket = servFactory.createServerSocket(PORT);
		} catch (IOException e) {
			System.out.println("Auth.Server: error creating server socket:"+e.getMessage());
		}
	}
	
	@Override
	public void run() {
		while(true) {
			try {
				System.out.println("Waiting for a new connection.");
				Thread con = new Thread(new AuthorisationServer(serverSocket.accept()));
				System.out.println("Auth.Server: New client connected.");
				con.start();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

}
