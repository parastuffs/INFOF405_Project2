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
		String t = this.takeFile("src/Crypt.class.php");
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
			//4 lignes de code :
//			Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding"); //defini que c'est AES en mode CBC
//			aes.init(Cipher.DECRYPT_MODE, CLEF, new IvParameterSpec(new byte[16])); //voir commentaire en dessous
//			String cleartext = new String(aes.doFinal(ciphertext));
//			return cleartext;
			/*
			dans aes.init() : il faut la clef AES (un objet de type Key) pour dechiffrer
			et new IvParameter = vecteur d'initialisation (faut utiliser le meme pour encrypter/decrypter)
			par ex. un array de 16 bytes a zero
			derniere ligne : ciphertext = texte a dechiffrer, c'est le "text" du parametre ici?
			cleartext etant le texte clair, dechiffre.
			il reste encore le salt que je sais pas où il doit se mettre, ni a quoi sert le parametre "type"

			si tu veux generer une cle, tu as la fonction implementee generateAESKey() 
			dans la classe AuthorisationServer.java 
			*/
			return "";//TODO a verifier
			//IMPORTANT!!!!! Decryptage rijndael-128 mode cfb a mettre en place 
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
			//4 lignes de code :
//			Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding"); //defini que c'est AES en mode CBC
//			aes.init(Cipher.ENCRYPT_MODE, CLEF, new IvParameterSpec(new byte[16])); //voir commentaire en dessous
//			byte[] ciphertext = aes.doFinal("my_cleartext".getBytes());
//			return new String(ciphertext, "UTF-8"); //a tester; bete conversion byte[]->string
			
			//dans aes.init() : il faut la clef AES (un objet de type Key) pour chiffrer
			//et new IvParameter = vecteur d'initialisation (faut utiliser le meme pour encrypter/decrypter)
			//par ex. un array de 16 bytes a zero
			//derniere ligne : my_cleartext est le texte clair a chiffrer, c'est "text" (parametre)?
			
			//il reste encore le salt que je sais pas où il doit se mettre, ni a quoi sert le parametre "type"
		
            return "";//TODO             IMPORTANT!!!!! Cryptage rijndael-128 mode cfb � mettre en place (si probleme de mode ou quoi, je peux encore le changer)
		}
	}
	
	/**
	 * Give back the corresponding password or nothing if no password
	 */
	public String password(String type, String salt)
	{
		Map<String, String> pass = new HashMap<String, String>();
		pass.put("WS1", this.sha1("564zecv41zFEFEZ"+this.mainKey+"f4fl"+salt+"pOInjfoezi1zefzeggezezf"));
		pass.put("WS2", this.sha1("564zecv42zFEFEZ"+this.mainKey+"f4fl"+salt+"pOInjfoezi2zefzeggezezf"));
		pass.put("publicKey", this.sha1("ZOiknfeziFZE49f"+this.mainKey+"FZplkFZA549"+salt+"55878zefFE"));
		pass.put("privateKey", this.sha1("ZDKfezjFEZ"+salt+"MPOKVFDFGBVSZDZ55669"+this.mainKey+"ZQjinodz"+salt+"558"));
		pass.put("sessionKey", this.sha1("DZAkoncqazsc"+salt+"FZE1fez5ez5fFEZfzesPOI"+this.mainKey+"ZEFiouijfeznoief66989"+salt+"558"));
		pass.put("keyOrigin", this.sha1("KIJ535NFEijncszec"+this.mainKey+"gecv558"));
		pass.put("keyDestination", this.sha1("FEZFEZEFZfezfddsfsdfrFE"+this.mainKey+"ec54469gre8"));
		pass.put("passwordUsername", this.sha1("FZEFEZdslmiue"+this.mainKey+"zefzfe0979"+this.mainKey+"8IKpml558"));
		pass.put("hashedUsername", this.sha1("uDZIubnDZF"+salt+"DFZEAijfd546"+this.mainKey+"vfDZA56ffe"));
		pass.put("hashedId", this.sha1("fsez9ef"+salt+"gfEgfr569z6"+this.mainKey+"cgr5g66EGF8"));
		
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
