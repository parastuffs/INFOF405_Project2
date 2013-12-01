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
            
            echo '<center>';
            echo 'It seems that you have just launched for the first time the web interface.<br/>';
            echo 'Take the files below to have your public & private keys, and your certificate for the different websites.<br/>';
            echo 'If you do not take themnow, they are still accessible on the specific page. But if you download them a second time<br/>';
            echo 'you will only have the public key in it. Be sure to never lose the files with public+private keys and to destroy them<br/>';
            echo 'after sending them to the appropriate client/server.<br/><br/>';
            
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
                echo '<strong>Keys & certificate for '.$value.'</strong><br/>';
                echo 'Key: <a href="'.$keys['link'].'" target="__blank">click here</a><br/>';
                echo 'Certificate: <a href="'.$keys['linkCertificate'].'" target="__blank">click here</a><br/><br/>';
                
            }
            echo '</center>';
        }
    }
    
}

?>