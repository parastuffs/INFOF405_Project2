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
     * Return the keys for the different web service, if there is none, automatically create them
     * @param $idWS the id of the WS (1 or 2)
     * @return array('publicKey'=>String,'privateKey'=>String)
     */
    public function getKeys($idWS)
    {
        
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