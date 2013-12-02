package webservice;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SealedObject;

public class Keychain extends WebService {
	private static final int KEY_PORT = 2014; //keychain port
	private static final int KEY_ID = 2; //keychain service ID
	private final int SHOW = 0; //show the passwords
	private final int ADD = 1; //add a new password
	
	public Keychain() {
		super(KEY_PORT,KEY_ID);
	}
	
	@Override
	protected void answerClientRequest(int requestType, String reqMsg, int clientID, ObjectOutputStream out){
		if(requestType!=SHOW || requestType!=ADD)
			System.out.println("Keychain: invalid request");
		else {
			if(requestType==SHOW) {
				//collect all the passwords of the client from the DB
				ArrayList<String> message = KeychainDB.getInstance().getMyPasswords(clientID);
				try {
					//encrypt the result with the AES key
					SealedObject encryptedMsg = new SealedObject(message,
							this.getCipherOfSharedKey(super.getClientKey(clientID), ENCRYPT));
					//send it to client
					out.writeObject(encryptedMsg);
				} catch (IllegalBlockSizeException | IOException e) {
					System.out.println("Keychain answering to client: error:" + e.getMessage());
					e.printStackTrace();
				}
			} else if(requestType==ADD && !reqMsg.isEmpty()) {
				boolean success = KeychainDB.getInstance().addNewPass(clientID, reqMsg);
				if(success)
					System.out.println("Keychain: new password added with success");
				else
					System.out.println("Keychain: error on adding new password");
			}
		}
	}

	public static void main(String[] args) {
		new Keychain();
		KeychainDB.getInstance().closeConnection();
		System.out.println("Keychain web service terminated");
	}
}
