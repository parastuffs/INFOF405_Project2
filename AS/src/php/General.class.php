<?php 
/* Important notice !
 
Is it really useful to create a specific salt for each person btw :/? If we use a common salt, isn't it ok also :/? 
Do not forget to activate the "open_ssl" module in wamp!

TODO : en fait, il faut peut-être vérifier lors de la création d'un mot de passe et d'un iv qu'on est sûr de ne pas les avoir
utilisé par hasard ailleurs (probabilité infime mais bon)... Ou bien on écrit dans le rapport qu'on considère que c'est bon
comme ça... Mais en tout cas, il y le chiffrement des noms qui utilisent d'office le même password, donc il serait peut-être
intéressant de s'assurer que l'iv généré ne correspond à un autre précédemment utilisé...

TODO (IMPORTANT) : je ne connais pas le nom officiel de ce genre d'attaque, mais il faut générer un token valide pour un certain 
temps à rajouter à chaque url de page. J'expliquerai plus en détail l'attaque si vous ne voyez pas l'utilité ce token.
Note à moi-même: même si il n'y a pas de pass à la session d'utilisateur il suffit que l'admin reçoive un lien avec une url via
ses mails ou simplement sur un site web qu'il visite :/.

En fait, il dit que toutes les informations stockées dans la base de donnée doivent être chiffrées... C'est à prendre à la lettre
ça? Car chiffrer un salt, c'est pour le moins inutile...
*/

class General
{
    protected $db;
    protected $passwordForName = 'fekjplàç!FEZFEFZE777446638778fszefezèççç-^$m';
    protected $passwordForValidity = 'lkPDA^ùùµ$^7556866µ$^^µZpdFZEPApfez';
    
    public function __construct()
    {
        $this->connection();
    }
    
    /**
	 * This method allows us to connect to the database.
     * @return boolean
	 */
	public function connection()
	{		
		try
		{
			$this->db = new PDO('mysql:host=localhost;dbname=info405', 'root', '');//Second element: username, third element: password to the db.
            //$this->db = new PDO('mysql:host=localhost;dbname=info405', 'AS', 'EFZIOnjefzoinOEF5848zef8zefef');//Second element: username, third element: password to the db.
		}
		catch(Exception $e)
		{
			exit('Error : '.$e->getMessage().'<br />N° : '.$e->getCode().'<br/>');
		}
		
		return true;
	}	
 
      
    /**
     * Create a salt. If possible, we should use a specific function better to create random number than rand() and even mt_rand(), it's something like openssl...()  stuff
     * @param $minimum The minimum number of bytes of the salt
     * @return String (in a hexadecimal format but doesn't matter...)
     */
    public function createSalt($minimum=25)
    {    
        $crypto = true;
        $bytes = openssl_random_pseudo_bytes($minimum, $crypto);        
        return bin2hex($bytes);       
    }        
    
}


?>