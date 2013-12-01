package webservice;

public class Keychain extends WebService {
	private static final int KEY_PORT = 2014; //keychain port
	private static final int KEY_ID = 1; //keychain service ID
	
	public Keychain() {
		super(KEY_PORT,KEY_ID);
	}
	@Override
	protected void answerClientRequest() {
		// TODO Auto-generated method stub
		
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
	}
}
