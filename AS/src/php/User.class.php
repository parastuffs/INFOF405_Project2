<?php 

class User extends General
{
    /**
     * Insertion of the new client into the db
     * @param $name String the name of the client
     * @param $access array('WS1'=>bool,'WS2'=>bool) the access that the client have for each website
     * @return array('resultState'=>bool,'resultText'=>String,'id'=>int)
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
        $hname = Crypt::hashedUsername($name);
        $p = $this->db->prepare("SELECT id FROM user WHERE husername = :hname LIMIT 1");
		$p->execute(array('hname'=>$hname));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	                
        if(isset($vf['id']))
            return array('resultState'=>false, 'resultText'=>'Invalid user name! This username is already taken.');
       
        //Creation of the salt
        $salt = $this->createSalt();            
        
        //Encrypting of the important information (notice: we can use a salt for that).
        $cryptedName = Crypt::encrypt($name, Crypt::passwordUsername($salt));
        
        //We also crypt the access to WS1 and WS2 (we can now use the salt with no problem :))
        $WS1=0;
        $WS2=0;
        if($access['WS1'] === true)
            $WS1 = 1;
        if($access['WS2'] === true)
            $WS2 = 1;
          
        $cryptedWS1 = Crypt::encrypt($WS1,Crypt::passwordWS(1,$salt));
        $cryptedWS2 = Crypt::encrypt($WS2,Crypt::passwordWS(2,$salt));
        
        //Insertion into the db (user)
        $p = $this->db->prepare("INSERT INTO user VALUES (NULL, :username, :hname, :salt, :ws1, :ws2)");
		$p->execute(array('username'=>$cryptedName,'hname'=>$hname,'salt'=>$salt,'ws1'=>$cryptedWS1, 'ws2'=>$cryptedWS2));
		$p->closeCursor();	
        
        //We take the id of the user
        $p = $this->db->prepare("SELECT id FROM user WHERE username = :username ORDER BY id DESC LIMIT 1");
		$p->execute(array('username'=>$cryptedName));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	
        
        if(!isset($vf['id']))
            return array('resultState'=>false,'resultText'=>'The user wasn\'t inserted correctly into the db...');
        
        //Done :D
        return array('resultState'=>true, 'resultText'=>'Member successfully created!','id'=>$vf['id']);
    }
    
    /**
     * Delete a client
     * @param $id 'CL'.$idClient
     * @return array('resultState'=>bool,'resultText'=>String,'id'=>int)
     */
    public function deleteClient($id)
    {
        //Verification of the id of the client
        if(!preg_match('#^CL[0-9]{1,5}$#', $id))
            return array('resultState'=>false, 'resultText'=>'Invalid user id!');
        $id = explode('CL',$id);
        $id = $id[1];
        
        //Verification if there is a similar user into the db
        $p = $this->db->prepare("SELECT * FROM user WHERE id = :id LIMIT 1");
		$p->execute(array('id'=>$id));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	                
        
        if(!isset($vf['id']))
            return array('resultState'=>false, 'resultText'=>'This user is not in the db anymore!');
        
        //We delete all its information
        $p = $this->db->prepare("DELETE FROM user WHERE id = :id LIMIT 1");
		$p->execute(array('id'=>$id));
		$p->closeCursor();	        
        
        $p = $this->db->prepare("DELETE FROM asymkey WHERE owner = :owner LIMIT 1");
		$p->execute(array('owner'=>'CL'.$id));
		$p->closeCursor();	        
        
        $p = $this->db->prepare("DELETE FROM sessionkey WHERE horigin = :hid LIMIT 1");
		$p->execute(array('hid'=>Crypt::hashedId('CL'.$id)));
		$p->closeCursor();	
        
        //Done :).
        return array('resultState'=>true, 'resultText'=>'Client successfully deleted!');
    }   
    
}

?>