<?php 
/* Important notice !
As all the information must be encrypted into the db, I've decided to be a little paranoid and really encrypt the most
available information into it... So it is not possible to know for a hacker who stole the db how to join two tables first
of all thanks to the unique salt created for each person which is, in fact, like a password for the information stored
intot the db. The only uncrypted information are the id of each entry, as there are useless for the hackers there is no
need to encrypt them I think :).

Is it really useful to create a specific salt for each person btw :/? If we use a common salt, isn't it ok also :/? 

Do not forget to activate the "open_ssl" module in wamp!

TODO : en fait, il faut peut-être vérifier lors de la création d'un mot de passe et d'un iv qu'on est sûr de ne pas les avoir
utilisé par hasard ailleurs (probabilité infime mais bon)... Ou bien on écrit dans le rapport qu'on considère que c'est bon
comme ça...
*/

class General
{
    protected $db;
    
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
			$this->db = new PDO('mysql:host=;port=;dbname=info405', 'AS', 'EFZIOnjefzoinOEF5848zef8zefef');//Second element: username, third element: password to the db.
		}
		catch(Exception $e)
		{
			exit('Error : '.$e->getMessage().'<br />N° : '.$e->getCode().'<br/>');
		}
		
		return true;
	}	
 
          
    
}


?>