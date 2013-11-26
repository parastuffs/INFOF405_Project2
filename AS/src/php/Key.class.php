<?php 

/**
 * @see "http://php.net/manual/fr/book.openssl.php"
 * Y'a des trucs que je ne comprends pas vraiment, comme l'histoire de protéger les clefs par un mot de passe (que je n'ai pas implémenté mais openssl le permet grace aux paramètres passés)... C'est utile pour nous? 
 */
class Key extends General
{
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
     * @param $idWS the id of the WS (1 or 2), if it's for a client, it's 3
     * @return array('publicKey'=>String,'privateKey'=>String);
     */
    public function getAsymKeysIn($idWS)
    {
        //As we want the keys to send information to the WS, we need the keys that only have a public key and no private key
        //Because it means they were created by the WS and sent here
        
        $p = $GLOBALS['bdd']->prepare("SELECT * FROM key WHERE type = :ws AND validity=:valid AND privateKey is null ORDER BY creationDate DESC");
		$p->execute(array('ws'=>$idWS, 'valid'=>1));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	
        
        if(isset($vf['id']))
            return array('publicKey'=>Crypt::decrypt($vf['publicKey'], Crypt::passwordPublicKey($vf['salt'])),'privateKey'=>Crypt::decrypt($vf['privateKey'], Crypt::passwordPrivateKey($vf['salt'])));
        
        //We create the keys
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
     * Display the keys used by a user for both WS (if they exist)
     * @param $id int the id of the user
     * @return array('resultState'=>bool,'resultText'=>String)
     */
    public function changeUserAccess($id, $WS1, $WS2)
    {
    
    }
    
    /**
     * Revocation of specified asymmetric keys
     * @param $id the key id to revoke
     */
    public function revocationAsymmetric($id)
    {
    
    }
    
    /**
     * Revocation of specified symmetric keys
     * @param $id the key id to revoke
     */
    public function revocationSymmetric($id)
    {
    
    }
}

?>