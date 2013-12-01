package webservice;

public class Blackboard extends WebService {
	private static final int BL_PORT = 2013; //blackboard port
	private static final int BL_ID = 0; //blackboard service ID
	
	public Blackboard() {
		super(BL_PORT,BL_ID);
	}
	

	@Override
	protected void answerClientRequest() {
		// TODO Auto-generated method stub
		
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		new Blackboard();
	}
}
