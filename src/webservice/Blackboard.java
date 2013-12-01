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
	protected void answerClientRequest(int request, int clientID, ObjectOutputStream out) {
		if(request!=SHOW || request!=WRITE)
			System.out.println("Blackboard: invalid request");
		else {
			ArrayList<String> message = new ArrayList<String>();
			if(request==SHOW) {
				//collect all posts from the DB
				//TODO TESTING:
				message.add("Coucou");
				message.add("Deuxieme :D");
				message.add("Je sais pas quoi ecrire ici.");
			} else if(request==WRITE) {
				//TODO 
				message.add("wriiiiiiiiiiiiite");
			}
			try {
				//encrypt the result with the AES key
				SealedObject encryptedMsg = new SealedObject(message,
						this.getCipherOfSharedKey(super.getClientKey(clientID), ENCRYPT));
				//send it to client
				out.writeObject(encryptedMsg);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		new Blackboard();
	}
}
