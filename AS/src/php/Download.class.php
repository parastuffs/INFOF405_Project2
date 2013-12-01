<?php 

class Download extends General
{
    /**
     * Upload a file with the given keys. The private key will only be put in the file if it's the first time that we access to the key. Otherwise only the public key will be given
     * @param $idKey int the id of the key
     * @param $token String a special token to check that the person can access to the file (the keys are encrypted into the db).
     * @param $name String just a name used for the person who's gonna download this file
     * @param $certificate bool if true, we give the certificate file and not the key file.
     * @return array('resultState'=>bool,'resultText'=>String)
     */
    public static function getAsymKeyFile($idKey, $token, $name, $certificate=false)
    { 
        if(!preg_match('#^[a-zA-Z0-9]{1,25}$#',$name))
            $name = 'unknown';
        
        //We check the token
        if($token != Crypt::tokenKeyFile($idKey, $certificate))
            return array('resultState'=>false,'resultText'=>'Invalid url! You are a bad person...');
        
        //We check if the file with the private & public key is accessible, if not, it is not the first access to this page
        if($certificate === true && file_exists('src/files/key.'.$idKey.'.all.pem'))
            $link = 'src/files/key.'.$idKey.'.certificate.pem';        
        else if(file_exists('src/files/key.'.$idKey.'.all.pem'))
            $link = 'src/files/key.'.$idKey.'.all.pem';
        else if(file_exists('src/files/key.'.$idKey.'.pub.pem'))
            $link = 'src/files/key.'.$idKey.'.pub.pem';
        else
            return array('resultState'=>false,'resultText'=>'Hum... There is a problem... The file for this key does not exist.');
            
        //We decrypt the file
        $t = file_get_contents($link);
        $t = Crypt::decrypt($t, Crypt::passwordKeyFile($idKey));
                
        //We upload it
        header("Content-type:application/octet-stream");
        if($certificate === true)
            header('Content-Disposition: attachment; filename="key.'.$name.'.certificate.pem"');        
        else if(file_exists('src/files/key.'.$idKey.'.all.pem'))
            header('Content-Disposition: attachment; filename="key.'.$name.'.all.pem"');
        else 
            header('Content-Disposition: attachment; filename="key.'.$name.'.pub.pem"');
        
        flush();  
        echo $t;  
		flush();		  
        
        //If this was a file with public+private key, we delete it. Notice: we don't care if this the key for AS, the private key is still in the db.
        if(file_exists('src/files/key.'.$idKey.'.all.pem'))
            if(!@unlink('src/files/key.'.$idKey.'.all.pem'))
                return array('resulState'=>false,'resultText'=>'BIG PROBLEM! Impossible to delete the file src/files/key.'.$idKey.'.all.pem!');
                
        //Done.
        return array('resulState'=>true,'resultText'=>'Key file successfully sent!');
    }
    
    
    public static function createAsymKeyFile($idKey, $privateKey, $publicKey, $certificate, $ASkey=false)
    {
        //We create the main file only if this is not the AS key
        if($ASkey !== true)
        {
            $fic = fopen('src/files/key.'.$idKey.'.all.pem','w');
            fputs($fic, Crypt::encrypt($publicKey.$privateKey, Crypt::passwordKeyFile($idKey)));
            fclose($fic);
        }
        
        //We create the file for the public key
        $fic = fopen('src/files/key.'.$idKey.'.pub.pem','w');
        fputs($fic, Crypt::encrypt($publicKey, Crypt::passwordKeyFile($idKey)));
        fclose($fic);
        
        //We create the file for the certificate
        $fic = fopen('src/files/key.'.$idKey.'.certificate.pem','w');
        fputs($fic, Crypt::encrypt($certificate, Crypt::passwordKeyFile($idKey)));
        fclose($fic);
        
        return true;
    }
    
    public static function destroyAsymKeyFile($idKey)
    {
        if(file_exists('src/files/key.'.$idKey.'.all.pem'))
            @unlink('src/files/key.'.$idKey.'.all.pem');
       
        if(file_exists('src/files/key.'.$idKey.'.pub.pem'))
            @unlink('src/files/key.'.$idKey.'.pub.pem');
        
        if(file_exists('src/files/key.'.$idKey.'.certificate.pem'))
            @unlink('src/files/key.'.$idKey.'.certificate.pem');
    }
}

?>