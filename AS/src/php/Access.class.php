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
        if(!is_int($id) || $id < 0)
            return array('resultState'=>false,'resultText'=>'This user is not into the database.');
        
        //We take the user & check if he is in the db
        $p = $GLOBALS['bdd']->prepare("SELECT id, salt FROM user WHERE id = :id LIMIT 1");
		$p->execute(array('id'=>$id));
		$res = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();
        if(!isset($res['id']))
            return array('resultState'=>false,'resultText'=>'This user is not into the database.');
                
        //We change his information
        $WS1=0;
        $WS2=0;
        if($access['WS1'] === true)
            $WS1 = 1;
        if($access['WS2'] === true)
            $WS2 = 1;
          
        $cryptedWS1 = Crypt::encryptWS($WS1,Crypt::passwordWS(1,$res['salt']));
        $cryptedWS2 = Crypt::encryptWS($WS2,Crypt::passwordWS(2,$res['salt']));
        
        $p = $GLOBALS['bdd']->prepare("UPDATE user SET WS1=:ws1, WS2 = :ws2 WHERE id = :id LIMIT 1");
		$p->execute(array('ws1'=>$cryptedWS1,'ws2'=>$cryptedWS2,'id'=>$res['id']));
		$p->closeCursor();

        //Done.      
        return array('resultState'=>true,'resultText'=>'The authorizations for this user have been changed.');
    }
}

?>