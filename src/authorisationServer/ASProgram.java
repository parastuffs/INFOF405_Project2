package authorisationServer;

public class ASProgram {

	public static void main(String argv[]) {
		Thread AS = new Thread(new AuthorisationServer());
		AS.start();
	}
}
