package webservice;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SealedObject;

public class Blackboard extends WebService {
	private static final int BL_PORT = 2013; //blackboard port
	private static final int BL_ID = 1; //blackboard service ID
	private final int SHOW = 0; //show the posts
	private final int WRITE = 1; //add a new post
	
	public Blackboard() {
		super(BL_PORT,BL_ID);
	}
	

	@Override
	protected void answerClientRequest(int requestType, String reqMsg, int clientID, ObjectOutputStream out) {
		if(requestType!=SHOW || requestType!=WRITE)
			System.out.println("Blackboard: invalid request");
		else {
			if(requestType==SHOW) {
				//collect all posts of the client from the DB
				ArrayList<String> message = BlackboardDB.getInstance().getMyPosts(clientID);
				try {
					//encrypt the result with the AES key
					SealedObject encryptedMsg = new SealedObject(message,
							this.getCipherOfSharedKey(super.getClientKey(clientID), ENCRYPT));
					//send it to client
					out.writeObject(encryptedMsg);
				} catch (IllegalBlockSizeException | IOException e) {
					System.out.println("Blackboard answering to client: error:" + e.getMessage());
					e.printStackTrace();
				}
			} else if(requestType==WRITE && !reqMsg.isEmpty()) {
				boolean success = BlackboardDB.getInstance().writeOnBoard(clientID, reqMsg);
				if(success)
					System.out.println("Blackboard: new message written with success");
				else
					System.out.println("Blackboard: error on writing new message");
			}
		}
	}
	
	public static void main(String[] args) {
		new Blackboard();
		BlackboardDB.getInstance().closeConnection();
		System.out.println("Blackboard web service terminated");
	}
}
