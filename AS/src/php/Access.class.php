<?php 

class Access extends General
{    
    /**
     * Listing the access control list / users with their access 
     * @param $page int
     * @return array('resultState'=>bool,'resultText'=>String,'nbrPages'=>int,'user'=>array(array('username'=>String,'WS1'=>bool,'WS2'=>bool)), etc.)
     */
    public function listAccessControl($page)
    {
        if(!is_int($page) || $page < 0 || $page > 10000)
            $page = 0;
        $start = $page*25;
        $end = ($page+1)*25-1;
        
        //We take the number of pages
        $p = $GLOBALS['bdd']->query("SELECT COUNT(*) AS tot FROM user");
		$res = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();
        $tot = ceil($res['tot']/25);
        if($page > $res)
            return array('resultState'=>false,'resultText'=>'Invalid number of page...','nbrPages'=>$tot);
        
        //We take the entries
        $p = $GLOBALS['bdd']->query("SELECT * 
                                        FROM user 
                                        ORDER BY id
                                        LIMIT ".$start.", ".$end);
		$res = $p->fetchAll(PDO::FETCH_ASSOC);
		$p->closeCursor();	                
        
        //We decrypt the different access
        $tab=array('resultState'=>true,'resultText'=>'','nbrPages'=>$tot,'user'=>array());
        foreach($res as $key => $value)
        {
            $username = Crypt::decrypt($res[$key]['username'], $this->passwordForName);
            $WS1 = Crypt::decrypt($res[$key]['WS1'], Crypt::passwordWS(1,$res[$key]['salt']));
            $WS2 = Crypt::decrypt($res[$key]['WS2'], Crypt::passwordWS(2,$res[$key]['salt']));
            $tab['user'][] = array('username'=>$username,'WS1'=>$WS1,'WS2'=>$WS2);
        }
        
        //Done.
        return array('resultState'=>true, 'resultText'=>'', $tab;        
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