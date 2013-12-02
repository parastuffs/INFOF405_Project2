package authorisationServer;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;


public class DatabasePassword {
	
	private String mainKey="";
	
	public DatabasePassword()
	{
		this.takeMainPassword();
	}
	
	/**
	 * Take the content of the file which contains a important password for all the passwords used by the webinterface and analyze it, then give back the information
	 * @return String or empty if nothing found.
	 */
	private String takeMainPassword()
	{
		//We take the file and analyze it
		String t = this.takeFile("AS/src/php/Crypt.class.php");
		String inf[];
		
		inf = t.split("const SPECIFIC_SALT \\= \"");
		if(inf.length <= 1)
			return "";
		
		inf = inf[1].split("\";");
		t = inf[0];
		
		//We have the key :).
		this.mainKey = t;
		return t;
	}
	
	/**
	 * Take the content of a file
	 * @param link the file to take
	 * @return
	 */
	private String takeFile(String link)
	{
		String line, text="";
		char specialLetter = 146;//We sometimes read into the file the character ' (apostrophe) which isn't correctly read, so we have to change the character read (146) 
				
		//We take the text inside
		try
		{			
			RandomAccessFile f = new RandomAccessFile(link,"r");
			
			while((line = f.readLine()) != null)
			{		
				line = line.replace(specialLetter, '\'');
				line = line.replace('\t', ' ');
				line = line.replace('\r', ' ');
				
				text += line;				
			}			
				
			f.close();
		}
		catch(IOException e)
		{
			System.out.println("Problem to open the file");
			e.printStackTrace();
		}
		
		return text;
	}
	
	/**
	 * Decrypt the information if there is a password used, if not, we just send back the same text
	 * @param type String the information type (WS, publicKey, privateKey, etc.)
	 * @param texte String
	 * @param salt String the salt used
	 * @return texte
	 */
	public String decrypt(String type, String text, String salt)
	{
		String pass="";
		
		//We check if there is a password
		pass = this.password(type, salt);
		
		if(pass.isEmpty())
		{//There is nothing to do...
			return text;
		}
		else
		{//We decrypt the text
			return "";//TODO             IMPORTANT!!!!! Decryptage rijndael-128 mode cfb � mettre en place (si probleme de mode ou quoi, je peux encore le changer)
		}
	}
	

	/**
	 * Crypt the information if there is a password used, if not, we just send back the same text
	 * @param type String the information type (WS, publicKey, privateKey, etc.)
	 * @param texte String
	 * @param salt String the salt to use
	 * @return texte
	 */
	public String crypt(String type, String text, String salt)
	{
		String pass="";
		
		//We check if there is a password
		pass = this.password(type, salt);
		
		if(pass.isEmpty())
		{//There is nothing to do...
			return text;
		}
		else
		{//We crypt the text
			
            return "";//TODO             IMPORTANT!!!!! Cryptage rijndael-128 mode cfb � mettre en place (si probleme de mode ou quoi, je peux encore le changer)
		}
	}
	
	/**
	 * Give back the corresponding password or nothing if no password
	 */
	private String password(String type, String salt)
	{
		Map<String, String> pass = new HashMap<String, String>();
		pass.put("WS1", this.sha1("564zecv41zFEFEZ"+this.mainKey+"f4fl"+salt+"p^dz^l^p)��1!�!��'"));
		pass.put("WS2", this.sha1("564zecv42zFEFEZ"+this.mainKey+"f4fl"+salt+"p^dz^l^p)��2!�!��'"));
		pass.put("publicKey", this.sha1("^�)��!���)"+this.mainKey+"�FEFEZ��"+salt+"$55878zefFE"));
		pass.put("privateKey", this.sha1("^��$$^"+salt+"�$��$$��$czq$�$�cqsd$�q"+this.mainKey+"$�dqscv"+salt+"$558"));
		pass.put("sessionKey", this.sha1("^��$$^"+salt+"�56zef169ez1f56e�!�!�"+this.mainKey+"�)$^�fezfezfezgecv"+salt+"$558"));
		pass.put("keyOrigin", this.sha1("�)��)&�)��z"+this.mainKey+"gecv$558"));
		pass.put("keyDestination", this.sha1("�)��F4fez9E"+this.mainKey+"ecv$558"));
		pass.put("passwordUsername", this.sha1("�45fzae"+this.mainKey+"zefzfe0979"+this.mainKey+"8IKpml$558"));
		pass.put("hashidUsername", this.sha1("�)��F45���!"+salt+"�fez9Eec"+this.mainKey+"v$558"));
		pass.put("hashedId", this.sha1("�EFZEF��!"+salt+"�fezrthtr"+this.mainKey+"cv$558"));
		
		if(!pass.containsKey(type))
		{
			System.out.println("[Pas de pass] Type: "+type+", Salt:"+salt);
			return "";
		}
		else
		{
			return pass.get(type);
		}
	}
	/**
	 * make a sha1 hash on a given text 
	 */
	public String sha1(String text)
	{
		return DigestUtils.sha1Hex(text);
	}
}
