<?php 

class Communication extends General
{   

    /**
     * Send a message to a specified WS server : we use a valid public key from the db, even if it is to revoke this key and giving another
     * @param $idWS int
     * @param $method String the method to call into the class Communication on the other server
     * @param $info array the informations to give to the specied server
     * @return array the information given in response by the other server
     */
    public function send($idWS, $method, $info)
    {
        
    
    }
    
}


?>