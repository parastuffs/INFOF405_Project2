package client;

import java.util.TimerTask;

public class TimerKey  extends TimerTask{

	private Client c;
	
	public TimerKey(Client c) {
		super();
		this.c = c;
	}
	
	@Override
	public void run() {
		c.destroyAESKeyWS1();
	}

	
	
}
