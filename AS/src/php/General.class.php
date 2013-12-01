<?php 

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