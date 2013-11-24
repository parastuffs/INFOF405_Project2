<?php 

class Access extends General
{    
    /**
     * Listing the access control list 
     * @param $page int
     * @return array('resultState'=>bool,'resultText'=>String,'nbrPages'=>int,'user'=>array('username'=>String,'WS1'=>bool,'WS2'=>bool))
     */
    public function listAccessControl($page)
    {
    
    }
        
    /**
     * Change the access to a webservice for a user
     * @param $id int the id of the user
     * @param $WS1 bool the new access to WS1
     * @param $WS2 bool the new access to WS2
     * @return array('resultState'=>bool,'resultText'=>String)
     */
    public function changeUserAccess($id, $WS1, $WS2)
    {
    
    }
}

?>