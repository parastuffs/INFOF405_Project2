<?php 

/**
 * @see "http://php.net/manual/fr/book.openssl.php"
 * Y'a des trucs que je ne comprends pas vraiment, comme l'histoire de protéger les clefs par un mot de passe (que je n'ai pas implémenté mais openssl le permet grace aux paramètres passés)... C'est utile pour nous? 
 */
class Key extends General
{
    const TIME_SESSION_KEY = 36000;//The time a session key is valid (10 hours here)
    
    /**
     * Creation of a public and private keys
     * @return array('resultState'=>bool,'resultText'=>String,'publicKey'=>String,'privateKey'=>String)
     */
    public function create()
    {
        //We make the configuration for the creation of keys (@see "http://www.php.net/manual/fr/function.openssl-csr-new.php" for the config array)
        $config = array(
                'digest_alg' => 'sha512',
                'private_key_bits' => 4096,
                'private_key_type' => 'OPENSSL_KEYTYPE_RSA',//it's the default type, but like that we directly see that we use RSA                
                );
        
        //We generate the private and public keys
        $keys = openssl_pkey_new($config);
        
        //We take the private key
        openssl_pkey_export($keys, $privateKey);
        
        //We take the public key
        $publicKey = openssl_pkey_get_details($keys);
        $publicKey = $publicKey['key'];
        
        //Done.
        return array('resultState'=>true,'resultText'=>'Keys successfully created!','publicKey'=>$publicKey,'privateKey'=>$privateKey);
    }
    
    /**
     * Return the asymetric keys that the other WS or client have to use to access to this website. If there is none, they're created
     * @return array('publicKey'=>String,'privateKey'=>String);
     */
    public function getAsymKeysIn()
    {        
        $p = $GLOBALS['bdd']->prepare("SELECT * FROM key WHERE type = :ws AND validity=:valid AND privateKey is not null ORDER BY creationDate DESC LIMIT 1");
		$p->execute(array('ws'=>'AS', 'valid'=>1));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	
        
        if(isset($vf['id']))
            return array('publicKey'=>Crypt::decrypt($vf['publicKey'], Crypt::passwordPublicKey($vf['salt'])),'privateKey'=>Crypt::decrypt($vf['privateKey'], Crypt::passwordPrivateKey($vf['salt'])));
        
        //If there is none, they're created (but we should display a message that's not the right way to access to get new keys)
        $keys = $this->create();
        
        //We generate a salt
        $salt = $this->createSalt();
        
        $cryptedPublicKey = Crypt::encrypt($keys['publicKey'], Crypt::passwordPublicKey($salt));
        $cryptedPrivateKey = Crypt::encrypt($keys['privateKey'], Crypt::passwordPrivateKey($salt));
        
        //We insert them into the db
        $p = $GLOBALS['bdd']->prepare("INSERT INTO key VALUES (NULL, :type, :publicKey, :privateKey, :creationDate, :salt, :validity)");
		$p->execute(array('type'=>$idWS,'publicKey'=>$cryptedPublicKey,'privateKey'=>$cryptedPrivateKey,'creationDate'=>time(),'salt'=>$salt,'validity'=>1));
		$p->closeCursor();	
        
        //Done.
        return array('publicKey'=>$keys['publicKey'],'privateKey'=>$keys['privateKey']);
    }   
    
    /**
     * Return a new symetric key to be used to communicate. If it's a client, change the below 'ID_CLIENT' by their id.
     * @param $origin the origin (one from these: 'WS1', 'WS2', 'AS', 'ID_CLIENT)
     * @param $destination the destination (one from these: 'WS1', 'WS2', 'AS', 'ID_CLIENT')
     * @return array('key'=>String,'validityTime'=>int);
     */
    public function getNewSymKeys($origin, $destination)
    {
        //We create the symetric key based on a salt
        $key = $this->createSalt(50);
        
        //We generate another salt
        $salt = $this->createSalt();
        
        $cryptedKey = Crypt::encrypt($key, Crypt::passwordSessionKey($salt));
        $origin = Crypt::encrypt($origin, Crypt::passwordKeyOrigin($salt));
        $destination = Crypt::encrypt($destination, Crypt::passwordKeyDestination($salt));
        
        //We insert them into the db
        $p = $GLOBALS['bdd']->prepare("INSERT INTO sessionkey VALUES (NULL, :key, :origin, :destination, :salt, :creationDate, :validity)");
		$p->execute(array('key'=>$cryptedKey,'origin'=>$origin,'destination'=>$destination,'creationDate'=>time(),'salt'=>$salt,'validity'=>1));
		$p->closeCursor();	
        
        //We return the created key and the time it is valid.
        return array('key'=>$key,'validityTime'=>self::TIME_SESSION_KEY);
    }    
    
    /**
     * Display all the symetric keys used by a user (the most recent first)
     * @param $id int the id of the user
     * @return array('resultState'=>bool,'resultText'=>String,'keys'=>array($id=>array('key'=>String,'origin'=>String,'destination'=>String),...))
     */
    public function displayUserKeys($id)
    {
        if(!is_int($id) || $id < 0)
            return array('resultState'=>false,'resultText'=>'Invalid user id.');
            
        $p = $GLOBALS['bdd']->prepare("SELECT * FROM user WHERE id = :id ORDER BY creationDate DESC");
		$p->execute(array('id'=>$id));
		$res = $p->fetchAll(PDO::FETCH_ASSOC);
		$p->closeCursor();
        
        //We decrypt the keys
        $tab = array('resultState'=>true,'resultText'=>'','keys'=>array());
        foreach($res as $key => $value)
        {
            $key = Crypt::decrypt($res[$key]['key'], Crypt::passwordSessionKey($res[$key]['salt']));
            $origin = Crypt::decrypt($res[$key]['origin'], Crypt::passwordKeyOrigin($res[$key]['salt']));
            $destination = Crypt::decrypt($res[$key]['destination'], Crypt::passwordKeyDestination($res[$key]['salt']));
            $tab['keys'][$res[$key]['id']] = array('key'=>$key,'origin'=>$origin,'destination'=>$destination);
        }
        
        //Done.
        return $tab;
    }
    
    /**
     * Revocation of a specified asymmetric key into the db (but we have to send the information to the concerned WS or client too!)
     * @param $id the key id to revoke
     * @return array('resultState'=>bool,'resultText'=>String)
     */
    public function revocationAsymmetricKey($id)
    {
        if(!is_int($id) || $id < 0)
            return array('resultState'=>false,'resultText'=>'Invalid asymetric key id.');
        
        //We take the key  
        $p = $GLOBALS['bdd']->prepare("SELECT * FROM key WHERE id = :id AND validity = 1");
		$p->execute(array('id'=>$id));
		$res = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();
        
        if(!isset($res['id']))
            return array('resultState'=>false,'resultText'=>'This key is not into the db or it is already revoked.');
            
        //We revoke the key
        $p = $GLOBALS['bdd']->prepare("UPDATE key SET validity=:validity WHERE id = :id LIMIT 1");
		$p->execute(array('validity'=>2,'id'=>$id));
		$p->closeCursor();
        
        //Done.
        return array('resultState'=>true,'resultText'=>'Key successfully revoked');
    }
    
    /**
     * Revocation of a specified symmetric key into the db (but we have to send the information to the concerned WS or client too!)
     * @param $id the key id to revoke
     */
    public function revocationSymmetricKey($id)
    {
        if(!is_int($id) || $id < 0)
            return array('resultState'=>false,'resultText'=>'Invalid symetric key id.');
        
        //We take the key  
        $p = $GLOBALS['bdd']->prepare("SELECT * FROM sessionkey WHERE id = :id AND validity = 1");
		$p->execute(array('id'=>$id));
		$res = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();
        
        if(!isset($res['id']))
            return array('resultState'=>false,'resultText'=>'This key is not into the db or it is already revoked.');
            
        //We revoke the key
        $p = $GLOBALS['bdd']->prepare("UPDATE sessionkey SET validity=:validity WHERE id = :id LIMIT 1");
		$p->execute(array('validity'=>2,'id'=>$id));
		$p->closeCursor();
        
        //Done.
        return array('resultState'=>true,'resultText'=>'Key successfully revoked');
    }
}

?>