package webservice;

import java.io.ObjectOutputStream;

public class Keychain extends WebService {
	private static final int KEY_PORT = 2014; //keychain port
	private static final int KEY_ID = 2; //keychain service ID
	
	public Keychain() {
		super(KEY_PORT,KEY_ID);
	}
	@Override
	protected void answerClientRequest(int requestType, String reqMsg, int clientID, ObjectOutputStream out){
	}

	public static void main(String[] args) {
	}
}
