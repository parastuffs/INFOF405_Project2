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
     * @return array('resultState'=>bool,'resultText'=>String,'publicKey'=>String,'privateKey'=>String,'certificateSign'=>String,'certificate'=>String)
     */
    public function create()
    {
        //We make the configuration for the creation of keys (@see "http://www.php.net/manual/fr/function.openssl-csr-new.php" for the config array)
        $config = array(
                'digest_alg' => 'sha512',
                'private_key_bits' => 1024,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,//it's the default type, but like that we directly see that we use RSA                
                );
        
        //We generate the private and public keys
        $keys = @openssl_pkey_new($config);
        if($keys === false)
            exit('Problem with openssl... The server can\'t use it...');
        
        //We take the private key
        openssl_pkey_export($keys, $privateKey);
        
        //We take the public key
        $publicKey = openssl_pkey_get_details($keys);
        $publicKey = $publicKey['key'];
        
        //We create the certificate        
        $information = array(
            "countryName" => "BE",
            "stateOrProvinceName" => "Brussels",
            "localityName" => "Brussels",
            "organizationName" => "U.L.B.",
            "organizationalUnitName" => "U.L.B. IR team",
            "commonName" => "Delhaye, Degols, Streltsov",
            "emailAddress" => "gdegols@ulb.ac.be.com"
        );
        
        //Generate a certificate signing request
        $certificateSign = openssl_csr_new($information, $privateKey);
        
        //Generate a self-signed certificate valid during 365 days.
        $certificate = openssl_csr_sign($certificateSign, null, $privateKey, 365);
        openssl_csr_export($certificateSign, $csrout);
        openssl_x509_export($certificate, $certout);
        openssl_pkey_export($privateKey, $signPass, sha1('69zfe8949fze)àç!è!ç98'.Crypt::SPECIFIC_SALT));
        
        //Done.
        return array('resultState'=>true,'resultText'=>'Keys successfully created!','publicKey'=>$publicKey,'privateKey'=>$privateKey,'certificateSign'=>$csrout,'certificate'=>$certout,'signPass'=>$signPass);
    }
    
    /**
     * Return the asymetric key that the other WS or client have to use to access to a server.
     * @param $owner the server for which the keys are created. If 'AS' the private key is also saved. If "CL".$id it is a client
     * @return array('publicKey'=>String,'privateKey'=>String,'id'=>int,'link'=>String,'linkCertificate'=>String);
     */
    public function getAsymKeysIn($owner)
    {        
        $p = $this->db->prepare("SELECT * FROM asymkey WHERE owner = :ws AND validity=:valid ORDER BY validity, creationDate DESC LIMIT 1");
		$p->execute(array('ws'=>$owner, 'valid'=>1));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	
                
        if(isset($vf['id']))
        {
            //We create the link
            $token = Crypt::tokenKeyFile($vf['id'], false);     
            $link = '?page=download&amp;idKey='.$vf['id'].'&amp;token='.$token.'&amp;name='.$owner.'&amp;certificate=0';   
            $token = Crypt::tokenKeyFile($vf['id'], true);              
            $linkCertificate = '?page=download&amp;idKey='.$vf['id'].'&amp;token='.$token.'&amp;name='.$owner.'&amp;certificate=1';        
            
            $privateKey = '';
            if(!empty($vf['privateKey']))
                $privateKey = Crypt::decrypt($vf['privateKey'], Crypt::passwordPrivateKey($vf['salt']));
            return array('publicKey'=>Crypt::decrypt($vf['publicKey'], Crypt::passwordPublicKey($vf['salt'])),'privateKey'=>$privateKey,'id'=>$vf['id'],'link'=>$link,'linkCertificate'=>$linkCertificate);
        }
        else
            return array('publicKey'=>'','privateKey'=>'','id'=>'','link'=>'','linkCertificate'=>'');
    }   
    
    /**
     * Return a new asymetric key to be used to communicate. If it's a client, change the below 'ID_CLIENT' by their id.
     * @param $owner the origin (one from these: 'WS1', 'WS2', 'AS', 'CL'.$ID_CLIENT)
     * @return array('publicKey'=>String,'privateKey'=>String,'id'=>int,'link'=>String,'linkCertificate'=>String);
     */
    public function getNewAsymKey($owner)
    {
       $keys = $this->create();
        
        //We generate a salt
        $salt = $this->createSalt();
        
        $cryptedPublicKey = Crypt::encrypt($keys['publicKey'], Crypt::passwordPublicKey($salt));
        if($owner == 'AS')
            $cryptedPrivateKey = Crypt::encrypt($keys['privateKey'], Crypt::passwordPrivateKey($salt));
        else
            $cryptedPrivateKey = '';
        
        
        //We insert them into the db
        $p = $this->db->prepare("INSERT INTO asymkey VALUES (NULL, :owner, :publicKey, :privateKey, :creationDate, :salt, :validity)");
		$p->execute(array('owner'=>$owner,'publicKey'=>$cryptedPublicKey,'privateKey'=>$cryptedPrivateKey,'creationDate'=>time(),'salt'=>$salt,'validity'=>1));
		$p->closeCursor();	
        
        //We take the id
        $p = $this->db->prepare("SELECT * FROM asymkey WHERE owner = :ws AND validity=:valid ORDER BY creationDate DESC LIMIT 1");
		$p->execute(array('ws'=>$owner, 'valid'=>1));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	
        
        //We create the file and the link to it.
        Download::createAsymKeyFile($vf['id'], $keys['privateKey'], $keys['publicKey'], $keys['certificate'], $owner == 'AS');
        $token = Crypt::tokenKeyFile($vf['id'], false);     
        $link = '?page=download&amp;idKey='.$vf['id'].'&amp;token='.$token.'&amp;name='.$owner.'&amp;certificate=0';
        $token = Crypt::tokenKeyFile($vf['id'], true);     
        $linkCertificate = '?page=download&amp;idKey='.$vf['id'].'&amp;token='.$token.'&amp;name='.$owner.'&amp;certificate=1';        
        
        //We return the created key and the time it is valid.
        return array('publicKey'=>$keys['publicKey'],'privateKey'=>$keys['privateKey'],'id'=>$vf['id'],'link'=>$link,'linkCertificate'=>$linkCertificate);
    } 
    
    /**
     * Return the symetric key actually used between two servers
     * @param $origin 
     * @param $destination
     * @return array('key'=>String,'creationDate'=>int);
     */
    public function getSymKey($origin, $destination)
    {        
        $p = $this->db->prepare("SELECT * FROM sessionkey WHERE origin = :ori AND destination = :dest validity=:valid ORDER BY creationDate DESC LIMIT 1");
		$p->execute(array('ori'=>Crypt::encrypt($origin, Crypt::passwordKeyOrigin()),'dest'=>Crypt::encrypt($destination, Crypt::passwordKeyOrigin()),'valid'=>1));
		$vf = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();	
        
        if(isset($vf['id']))
            return array('key'=>Crypt::decrypt($vf['key'], Crypt::passwordSessionKey($vf['salt'])),'creationDate'=>$vf['creationDate']);
        else
            return array('key'=>'','creationDate'=>0);
    }
    
    /**
     * Return a new symetric key to be used to communicate. If it's a client, change the below 'ID_CLIENT' by their id.
     * @param $origin the origin (one from these: 'WS1', 'WS2', 'AS', 'CL'.$ID_CLIENT)
     * @param $destination the destination (one from these: 'WS1', 'WS2', 'AS', 'CL'.$ID_CLIENT)
     * @return array('key'=>String,'validityTime'=>int);
     */
    public function getNewSymKey($origin, $destination)
    {
        //We create the symetric key based on a salt
        $key = $this->createSalt(50);
        
        //We generate another salt
        $salt = $this->createSalt();
        
        $cryptedKey = Crypt::encrypt($key, Crypt::passwordSessionKey($salt));
        $origin = Crypt::encrypt($origin, Crypt::passwordKeyOrigin());
        $destination = Crypt::encrypt($destination, Crypt::passwordKeyDestination());
        
        //We insert them into the db
        $p = $this->db->prepare("INSERT INTO sessionkey VALUES (NULL, :key, :origin, :horigin, :destination, :hdestination, :salt, :creationDate, :validity)");
		$p->execute(array('key'=>$cryptedKey,'origin'=>$origin,'horigin'=>Crypt::hashedId($origin),'destination'=>$destination,'hdestination'=>Crypt::hashedId($destination),'creationDate'=>time(),'salt'=>$salt,'validity'=>1));
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
        $p = $this->db->prepare("SELECT * FROM sessionkey WHERE (horigin = :hid OR hdestination = :hid) ORDER BY validity, creationDate DESC");
		$p->execute(array('hid'=>Crypt::hashedId($id)));
		$res = $p->fetchAll(PDO::FETCH_ASSOC);
		$p->closeCursor();
        
        //We decrypt the keys
        $tab = array('resultState'=>true,'resultText'=>'','keys'=>array());
        foreach($res as $key => $value)
        {
            $key = Crypt::decrypt($res[$key]['key'], Crypt::passwordSessionKey($res[$key]['salt']));
            $origin = Crypt::decrypt($res[$key]['origin'], Crypt::passwordKeyOrigin());
            $destination = Crypt::decrypt($res[$key]['destination'], Crypt::passwordKeyDestination());
            $tab['keys'][$res[$key]['id']] = array('key'=>$key,'origin'=>$origin,'destination'=>$destination,'creationDate'=>date("d-m-Y at h",$res[$key]['creationDate']),'validity'=>$res[$key]['validity']);
        }
        
        //Done.
        return $tab;
    }
    
    /**
     * Revocation of a specified asymmetric key into the db (but we have to send the information to the concerned WS or client too!)
     * @param $id the id of the owner
     * @param $keyId the key id to revoke
     * @return array('resultState'=>bool,'resultText'=>String)
     */
    public function revocationAsymmetricKey($id, $keyId)
    {
        if(!preg_match('#^[0-9]{1,}$#',$keyId) || $keyId < 0)
            return array('resultState'=>false,'resultText'=>'Invalid asymetric key id.');
                
        if(!preg_match('#^(AS|WS1|WS2|CL[0-9]{1,5})$#',$id))
            return array('resultState'=>false,'resultText'=>'Invalid id of owner.');
            
        //We take the key  
        $p = $this->db->prepare("SELECT * FROM asymkey WHERE id = :id AND owner = :owner AND validity = '1' LIMIT 1");
		$p->execute(array('id'=>$keyId,'owner'=>$id));
		$res = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();
        
        if(!isset($res['id']))
            return array('resultState'=>false,'resultText'=>'This key is not into the db or it is already revoked.');
            
        //We revoke the key
        $p = $this->db->prepare("UPDATE asymkey SET validity = '0' WHERE id = :id AND owner = :owner AND validity = '1' LIMIT 1");
		$p->execute(array('id'=>$keyId,'owner'=>$id));
		$p->closeCursor();
        
        //We delete the associated files
        Download::destroyAsymKeyFile($keyId);
        
        //Done.
        return array('resultState'=>true,'resultText'=>'Key successfully revoked');
    }
    
    /**
     * Revocation of a specified symmetric key into the db (but we have to send the information to the concerned WS or client too!)
     * @param $id the id of the owner
     * @param $keyId the key id to revoke
     */
    public function revocationSymmetricKey($id, $keyId)
    {
        if(!is_int($keyId) || $keyId < 0)
            return array('resultState'=>false,'resultText'=>'Invalid symetric key id.');
        
        if(!preg_match('#^(AS|WS1|WS2|CL[0-9]{1,5})$#',$id))
            return array('resultState'=>false,'resultText'=>'Invalid id of owner.');
        
        //We take the key  
        $p = $this->db->prepare("SELECT * FROM sessionkey WHERE id = :id AND (horigin = :hid OR hdestination = :hid) AND validity = 1");
		$p->execute(array('hid'=>Crypt::hashedId($id),'id'=>$keyId));
		$res = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();
        
        if(!isset($res['id']))
            return array('resultState'=>false,'resultText'=>'This key is not into the db or it is already revoked.');
            
        //We revoke the key
        $p = $this->db->prepare("UPDATE sessionkey SET validity=:validity WHERE id = :id AND (horigin = :hid OR hdestination = :hid) LIMIT 1");
		$p->execute(array('validity'=>0,'hid'=>Crypt::hashedId($id),'id'=>$keyId));
		$p->closeCursor();
        
        //Done.
        return array('resultState'=>true,'resultText'=>'Key successfully revoked');
    }    
}

?>