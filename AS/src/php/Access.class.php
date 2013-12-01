<?php 

class Access extends General
{       
    private $generalToken='';
    
    /**
     * Listing the access control list / users with their access 
     * @param $page int
     * @return array('resultState'=>bool,'resultText'=>String,'nbrPages'=>int,'user'=>array($id=>array('username'=>String,'WS1'=>bool,'WS2'=>bool)), etc.)
     */
    public function listAccessControl($page)
    {
        if($page < 0 || $page > 10000 || !preg_match('#^[0-9]{1,4}$#',$page))
            return array('resultState'=>false,'resultText'=>'Invalid number of page...','user'=>array(),'nbrPages'=>0);
        
        $start = $page*25;
        $end = ($page+1)*25-1;
        
        //We take the number of pages
        $p = $this->db->query("SELECT COUNT(*) AS tot FROM user");
		$res = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();
        $tot = floor($res['tot']/25);
        if($page > $tot)
            return array('resultState'=>false,'resultText'=>'Invalid number of page...','user'=>array(),'nbrPages'=>$tot);
        
        //We take the entries
        $p = $this->db->query("SELECT * 
                                        FROM user 
                                        ORDER BY id
                                        LIMIT ".$start.", ".$end);
		$res = $p->fetchAll(PDO::FETCH_ASSOC);
		$p->closeCursor();	                
        
        //We decrypt the different access
        $tab=array('resultState'=>true,'resultText'=>'','nbrPages'=>$tot,'user'=>array());
        foreach($res as $key => $value)
        {
            $username = Crypt::decrypt($res[$key]['username'],  Crypt::passwordUsername($res[$key]['salt']));
            $WS1 = (Crypt::decrypt($res[$key]['WS1'], Crypt::passwordWS(1,$res[$key]['salt'])) == 1);
            $WS2 = (Crypt::decrypt($res[$key]['WS2'], Crypt::passwordWS(2,$res[$key]['salt'])) == 1);
            $tab['user'][$res[$key]['id']] = array('username'=>$username,'WS1'=>$WS1,'WS2'=>$WS2);
        }
        
        //Done.
        return $tab;        
    }
        
    /**
     * Change the access to a webservice for a user
     * @param $id int the id of the user
     * @param $type int the id of the WS ('WS1' or 'WS2')
     * @param $newAcces bool the new access to WS.$type
     * @return array('resultState'=>bool,'resultText'=>String)
     */
    public function changeUserAccess($id, $type, $newAccess)
    {    
        if(!preg_match('#^CL[0-9]{1,5}$#', $id))
            return array('resultState'=>false, 'resultText'=>'Invalid user id!');
        $id = explode('CL',$id);
        $id = $id[1];
        
        //We take the user & check if he is in the db
        $p = $this->db->prepare("SELECT id, salt, WS1, WS2 FROM user WHERE id = :id LIMIT 1");
		$p->execute(array('id'=>$id));
		$res = $p->fetch(PDO::FETCH_ASSOC);
		$p->closeCursor();
        if(!isset($res['id']))
            return array('resultState'=>false,'resultText'=>'This user is not into the database.');
                
        //We change his information
        $WS1 = Crypt::decrypt($res['WS1'],Crypt::passwordWS(1,$res['salt']));
        $WS2 = Crypt::decrypt($res['WS2'],Crypt::passwordWS(2,$res['salt']));
                
        if($type == 'WS1')
        {
            $WS1 = 0;
            if($newAccess === true)
                $WS1 = 1;
        }
        else
        {
            $WS2 = 0;
            if($newAccess === true)
                $WS2 = 1;
        }
          
        $cryptedWS1 = Crypt::encrypt($WS1,Crypt::passwordWS(1,$res['salt']));
        $cryptedWS2 = Crypt::encrypt($WS2,Crypt::passwordWS(2,$res['salt']));
        
        $p = $this->db->prepare("UPDATE user SET WS1=:ws1, WS2 = :ws2 WHERE id = :id LIMIT 1");
		$p->execute(array('ws1'=>$cryptedWS1,'ws2'=>$cryptedWS2,'id'=>$res['id']));
		$p->closeCursor();

        //Done.      
        return array('resultState'=>true,'resultText'=>'The authorizations for this user have been changed.');
    }
    
    /**
     * Verification if the general token of page is ok (there is no general token for the download page)
     * @param $page
     * @param $token
     * @return array('resultState'=>bool,'resultText'=>String)
     */
    public function verificationValidToken($page, $token)
    {
        //Why can't we just make a token based on a hour and a self::SPECIFIC_SALT? -> Because, if the admin goes to a page on another website
        //the internet browser sends sometimes the url where it comes from. So the website can take it and directly use it. The most secure 
        //way is to generate a new specific token for each page.
        
        //If we are at the index page there is no need of a token (and the admin will never has it anyway when he just logs in), same thing for the download (as it would need to have several tokens activated simultaneously). But there is no problem with that.
        if($page == 'download' || $page == 'index')
            return array('resultState'=>true,'resultText'=>'');
        
        //We take the token that should be used
        if(!file_exists('src/files/security.token'))
            return array('resultState'=>false,'resultText'=>'Please, go first to the main page of the website which is <a href="?page=index">index.php</a>. It is not to annoy you, it is a security measure.');
        
        if(Crypt::tokenGeneralUrl(file_get_contents('src/files/security.token')) == $token)
            return array('resultState'=>true,'resultText'=>'');
        else
            return array('resultState'=>false,'resultText'=>'Sorry this page will not be displayed. Why? Security measure. Cf. report.<br/>You cannot open two pages at the same time.');
    }
    
    /**
     * Create a new token and directly, but if there is already one created before, we give the same back
     * @return String
     */
    public function getGeneralToken()
    {
        if(empty($this->generalToken))
        {
            $this->generalToken = $this->createSalt();
            
            $fic = fopen('src/files/security.token','w');
            fputs($fic,$this->generalToken);
            fclose($fic);
        }
        
        return Crypt::tokenGeneralUrl($this->generalToken);
    }
}

?>