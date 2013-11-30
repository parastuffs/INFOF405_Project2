<?php 

class Ini extends General
{
    public function serverKeys()
    {
        //Check if there is already the servers WS1, WS2 & AS in the database, if not, insert them
        $p = $this->db->prepare("SELECT * FROM asymkey WHERE (owner = 'WS1' OR owner = 'WS2' OR owner = 'AS')");
        $p->execute();
        $vf = $p->fetchAll(PDO::FETCH_ASSOC);
        $p->closeCursor();	                
        
        if(count($vf) < 3)
        {//We add them
            $list = array('WS1','WS2','AS');
            
            foreach($list as $key => $value)
            {
                //We check if the server does not exist yet
                $ok = true;
                foreach($vf as $key2 => $value2)
                    if($vf[$key2]['id'] == $value)
                        $ok = false;
                if($ok === false)
                    continue;
                    
                //We create the keys
                $keys = $GLOBALS['Key']->getNewAsymKey($value);
                
                //We display them
                echo '<strong>Keys for '.$value.'</strong><br/>';
                echo '<strong>Public key:</strong>'.$keys['publicKey'].'<br/>';
                echo '<strong>Private key:</strong>'.$keys['privateKey'].'<br/>';
                echo '<hr/>';
            }
        }
    }
    
}

?>