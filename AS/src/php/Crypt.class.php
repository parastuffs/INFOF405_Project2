<?php 

class Crypt extends General
{
    const ALGO = 'rijndael-128';
    const MODE = 'cfb';
    
    /**
     * Allows to crypt the information with a given password 
     * @param $text the text to encrypt
     * @param $password the password
     * @return String (the encrypted text)
     */
    public static function encrypt($text, $password)
    {
        $password = pack('H*', sha1($password));
        
        //We create an iv -> It is very important to do that here to be sure we never choose the same iv+password to encrypt something.
        $ivSize = mcrypt_get_iv_size(self::ALGO, self::MODE);
        $iv =  mcrypt_create_iv($ivSize, MCRYPT_RAND);
        
        //We encrypt the text
        $text = mcrypt_encrypt(self::ALGO, $password, $text, self::MODE, $iv);
        
        //We add the iv to the cipher text (there is no problem to do that, it does not need to be secret)
        $text = $iv.$text;
        
        //We need to change the encoding of the text, otherwise some problems could appear with the characters when they are put into a file or a db
        $text = base64_encode($text);
        
        //Done :D
        return $text;
    }
    
     
    /**
     * Allows to decrypt an encrypted text (we do not need to take the iv as )
     * @param $text the text to decrypt
     * @param $password the password
     * @return String (the decrypted text)
     */
    public static function decrypt($text, $password)
    {
        $password = pack('H*', sha1($password));
        
        $text = base64_decode($text);
       
        //We take the iv from the cipher text
        $ivSize = mcrypt_get_iv_size(self::ALGO, self::MODE);
        $iv = susbtr($text, 0, $iv_size);
        
        //We take the real cipher text
        $text = susbtr($text, $iv_size);
        
        //We decrypt.
        $text = mcrypt_decrypt(self::ALGO, $password, $text, self::MODE, $iv);
        
        //Done :D!
        return $text;
    }     
    
    
    /**
     * Give back the password to a WS for the user table
     * @param $WS int the number of the WS
     * @param $salt string the salt
     * @return String
     */
    public static function passwordWS($WS, $salt)
    {        
        return '564zecv4'.$WS.'zFEFEZf4fl'.$salt.'p^dz^l^p)àç'.$WS.'!à!èç';
    }
    
    /**
     * Give back the password for a public key for the key table 
     * @param $salt string the salt
     * @return String
     */
    public static function passwordPublicKey($salt)
    {        
        return '^à)çà!çèç)§FEFEZµù'.$salt.'$55878zefFE';
    }
        
    /**
     * Give back the password for a private key for the key table 
     * @param $salt string the salt
     * @return String
     */
    public static function passwordPrivateKey($salt)
    {        
        return '^àù$$^'.$salt.'ù$ùù$$ùù$czq$ù$ùcqsd$ùq$ùdqscv'.$salt.'$558';
    }
    
    /**
     * Give back the password for a key for the sessionKey table 
     * @param $salt string the salt
     * @return String
     */
    public static function passwordSessionKey($salt)
    {        
        return '^àù$$^'.$salt.'ù56zef169ez1f56eç!è!çà)$^ùµfezfezfezgecv'.$salt.'$558';
    }
    
    /**
     * Give back the password for the origin for the sessionKey table
     * @return String
     */
    public static function passwordKeyOrigin()
    {        
        return 'à)àç)&é)éàzgecv$558';
    }
    
    /**
     * Give back the password for the destination for the sessionKey table
     * @return String
     */
    public static function passwordKeyDestination()
    {        
        return 'à)àçF4fez9"Eecv$558';
    }
    
    /**
     * Give back the password for the username for the user table
     * @param $salt
     * @return String
     */
    public static function passwordUsername($salt)
    {        
        return 'à45fzaezefzfe0979'.$salt.'8IKpml$558';
    }
    
    /**
     * Give back the hashed username
     * @param $username
     * @return String
     */
    public static function hashedUsername($username)
    {        
        return sha1('à)àçF45àè§è!'.$username.'èfez9"Eecv$558');
    }
}

?>