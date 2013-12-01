package webservice;

import java.io.ObjectOutputStream;

public class Keychain extends WebService {
	private static final int KEY_PORT = 2014; //keychain port
	private static final int KEY_ID = 2; //keychain service ID
	
	public Keychain() {
		super(KEY_PORT,KEY_ID);
	}
	@Override
	protected void answerClientRequest(int request, int clientID, ObjectOutputStream out){
		// TODO Auto-generated method stub
		
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
	}
}
