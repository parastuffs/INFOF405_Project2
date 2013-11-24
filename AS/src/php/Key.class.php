<?php 

class Key extends General
{
    /**
     * Creation of a public and private keys
     * @return array('resultState'=>bool,'resultText'=>String,'publicKey'=>String,'privateKey'=>String)
     */
    public function create()
    {
    
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
     * Revocation of specified keys
     * @param $id the key id to revoke
     */
    public function revocation($id)
    {
    
    }
}

?>