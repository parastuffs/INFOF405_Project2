<?php 
/* Important notice !
As all the information must be encrypted into the db, I've decided to be a little paranoid and really encrypt the most
available information into it... So it is not possible to know for a hacker who stole the db how to join two tables first
of all thanks to the unique salt created for each person which is, in fact, like a password for the information stored
intot the db. The only uncrypted information are the id of each entry, as there are useless for the hackers there is no
need to encrypt them I think :).
 -> Plus vraiment d'actualité en fait vu que j'ai rassemblé les deux tables en une... 
 
Is it really useful to create a specific salt for each person btw :/? If we use a common salt, isn't it ok also :/? 

Do not forget to activate the "open_ssl" module in wamp!

TODO : en fait, il faut peut-être vérifier lors de la création d'un mot de passe et d'un iv qu'on est sûr de ne pas les avoir
utilisé par hasard ailleurs (probabilité infime mais bon)... Ou bien on écrit dans le rapport qu'on considère que c'est bon
comme ça... Mais en tout cas, il y le chiffrement des noms qui utilisent d'office le même password, donc il serait peut-être
intéressant de s'assurer que l'iv généré ne correspond à un autre précédemment utilisé...

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
        //$this->connection();
    }
    
    /**
	 * This method allows us to connect to the database.
     * @return boolean
	 */
	public function connection()
	{		
		try
		{
			$this->db = new PDO('mysql:host=localhost;dbname=info405', 'AS', 'EFZIOnjefzoinOEF5848zef8zefef');//Second element: username, third element: password to the db.
		}
		catch(Exception $e)
		{
			exit('Error : '.$e->getMessage().'<br />N° : '.$e->getCode().'<br/>');
		}
		
		return true;
	}	
 
          
    
}


?>