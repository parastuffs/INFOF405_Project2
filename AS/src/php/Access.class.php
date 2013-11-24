<?php 

class Access extends General
{    
    /**
     * Listing the access control list / users with their access 
     * @param $page int
     * @return array('resultState'=>bool,'resultText'=>String,'nbrPages'=>int,'user'=>array('username'=>String,'WS1'=>bool,'WS2'=>bool))
     */
    public function listAccessControl($page)
    {
        if(!is_int($page) || $page < 0 || $page > 10000)
            $page = 0;
        $start = $page*25;
        $end = ($page+1)*25-1;
        
        //We take first the pages
        $p = $GLOBALS['bdd']->prepare("SELECT access.id as access_id, access.use FROM access WHERE username = :name");
		$p->execute(array('name'=>$name));
		$res = $p->fetchAll(PDO::FETCH_ASSOC);
		$p->closeCursor();	                
        
        //Then we create the query for the access table
        
        //We take the different access
        
        
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