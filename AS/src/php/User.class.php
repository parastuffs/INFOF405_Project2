<?php 

class User extends General
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
        if(is_array($access))
            if(!is_bool($access['WS1']) || !is_bool($access['WS2']))
                return array('resultState'=>false, 'resultText'=>'Invalid user name! It must only contain between 1 to 25 to the following character: a-z, A-Z, 0-9, ., _, -.');
        
        //Verification if there is not a similar username into the db
        $p = $GLOBALS['bdd']->prepare("SELECT id FROM user WHERE username = :name");
		$p->execute(array('name'=>$name));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	                
        if(isset($vf['id']))
            return array('resultState'=>false, 'resultText'=>'Invalid user name! This username is already taken.');
        
        //Creation of the salt
        $salt = $this->createSalt();
        
        //Encrypting of the important information (notice: we DO NOT use the salt previously created for that).
        $cryptedName = Cryptage::encrypt($name, $this->passwordForName);
        
        //Insertion into the db (user)
        $p = $GLOBALS['bdd']->prepare("INSERT INTO user VALUES (NULL, :username, :salt)");
		$p->execute(array('username'=>$cryptedName,'salt'=>$salt));
		$p->closeCursor();	
        
        //We take the id of the new user
        $p = $GLOBALS['bdd']->prepare("SELECT id WHERE username = :username");
		$p->execute(array('username'=>$cryptedName));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	
        $id = $vf['id'];        
       
        //We crypt the id user for the access table, like that the hacker cannot link the two tables. 
        $cryptedId = Cryptage::encrypt($id,'ezf45ç))à!è!à6zfSQfzef'.$salt.'lpfeziefz!'.$id.'à!èè!ç!');
        
        //We also crypt the access to WS1 and WS2
        $WS1=0;
        $WS2=0;
        if($access['WS1'] === true)
            $WS1 = 1;
        if($access['WS2'] === true)
            $WS2 = 1;
          
        $cryptedWS1 = Cryptage::encrypt($WS1,'564zecv4zF'.$id.'EFEZf4fl'.$salt.'p^dz^l^p)àç!à!èç');
        $cryptedWS2 = Cryptage::encrypt($WS2,'564zecv4zF'.$id.'EFEZf4fl'.$salt.'p^dz^l^p)àç!à!èç');
       
        //Insertion into the db (access)
        $p = $GLOBALS['bdd']->prepare("INSERT INTO access VALUES (NULL, :userId, :ws1, :ws2)");
		$p->execute(array('userId'=>$cryptedId,'ws1'=>$cryptedWS1,'ws2'=>$cryptedWS2));
		$p->closeCursor();	        
        
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