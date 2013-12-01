package client;

import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.spec.SecretKeySpec;

/**
 * Class handling the connection of the client with
 * the various services
 *
 */
public abstract class ClientCon {
	
	private final int PORT_AS = 42000;
	private final int PORT_WS1 = 2013;
	private final int WS1_PRINT = 0;
	private final int CLIENT_ID = 10;
	private final int AS_ID = 0;
	private final int WS1_ID = 1;
	private final int WS2_ID = 2;

}
