<?php 

class User extends Database
{
    /**
     * Insertion of the new client into the db
     * @param $name String the name of the client
     * @param $access array('WS1'=>bool,'WS2'=>bool) the access that the client have for each website
     * @return array('resultState'=>bool,'resultText'=>String)
     */
    public function insertNewClient($name, $access)
    {
        //Verification of the name of the client
        if(!preg_match('#^[a-zA-Z0-9._-]{1,25}$#', $name))
            return array('resultState'=>false, 'resultText'=>'Invalid user name! It must only contain between 1 to 25 to the following character: a-z, A-Z, 0-9, ., _, -.');
        
        //Verification of the access
        
        //Verification if there is not a similar username into the db
        $p = $GLOBALS['bdd']->prepare("SELECT id FROM user WHERE username = :name");
		$p->execute(array('name'=>$name));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	                
        if(isset($vf['id']))
            return array('resultState'=>false, 'resultText'=>'Invalid user name! This username is already taken.');
        
        //Creation of the salt
        
        //Encrypting of the important information.
        
        //Insertion into the db (user)
        $p = $GLOBALS['bdd']->prepare("INSERT INTO user VALUES ( , :username, :salt)");
		$p->execute(array('username'=>$name,'salt'=>$salt));
		$p->closeCursor();	
       
        //Insertion into the db (access)
       
        //Done :D
        return array('resultState'=>true, 'resultText'=>'Member successfully created!');
    }
    
    /**
     * Create a salt. If possible, we should use a specific function better to create random number than rand() and even mt_rand(), it's something like openssl...()  stuff
     * @return String
     */
    private function createSalt()
    {
    
    }    
}
?>