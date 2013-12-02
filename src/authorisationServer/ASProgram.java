package authorisationServer;

public class ASProgram {

	public static void main(String argv[]) {
		//Thread AS = new Thread(new AuthorisationServer());
		Thread AS = new Thread(new ASConnectionHandler());
		AS.start();
	}
}
