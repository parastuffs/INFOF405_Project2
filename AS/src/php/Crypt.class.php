<?php 

class Crypt extends General
{
    const ALGO = 'rijndael-128';
    const MODE = 'cbc';
    
    //Specific salt which is load at the creation of the website to avoid the "sécurité par l'aveugle". DO NOT change the following line manually! Not even a space. NEVER.
    const SPECIFIC_SALT = "be982414e70f5b7dcfb2f6ad24b607405b0c42fc";
    
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
        $iv = substr($text, 0, $ivSize);
        
        //We take the real cipher text
        $text = substr($text, $ivSize);
        
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
        return sha1('564zecv4'.$WS.'zFEFEZ'.self::SPECIFIC_SALT.'f4fl'.$salt.'pOInjfoezi'.$WS.'zefzeggezezf');
    }
    
    /**
     * Give back the password for a public key for the key table 
     * @param $salt string the salt
     * @return String
     */
    public static function passwordPublicKey($salt)
    {        
        return sha1('ZOiknfeziFZE49f'.self::SPECIFIC_SALT.'FZplkFZA549'.$salt.'55878zefFE');
    }
        
    /**
     * Give back the password for a private key for the key table 
     * @param $salt string the salt
     * @return String
     */
    public static function passwordPrivateKey($salt)
    {        
        return sha1('ZDKfezjFEZ'.$salt.'MPOKVFDFGBVSZDZ55669'.self::SPECIFIC_SALT.'ZQjinodz'.$salt.'558');
    }
    
    /**
     * Give back the password for a key for the sessionKey table 
     * @param $salt string the salt
     * @return String
     */
    public static function passwordSessionKey($salt)
    {        
        return sha1('DZAkoncqazsc'.$salt.'FZE1fez5ez5fFEZfzesPOI'.self::SPECIFIC_SALT.'ZEFiouijfeznoief66989'.$salt.'558');
    }
    
    /**
     * Give back the password for the origin for the sessionKey table
     * @return String
     */
    public static function passwordKeyOrigin()
    {        
        return sha1('KIJ535NFEijncszec'.self::SPECIFIC_SALT.'gecv558');
    }
    
    /**
     * Give back the password for the destination for the sessionKey table
     * @return String
     */
    public static function passwordKeyDestination()
    {        
        return sha1('FEZFEZEFZfezfddsfsdfrFE'.self::SPECIFIC_SALT.'ec54469gre8');
    }
    
    /**
     * Give back the password for the username for the user table
     * @param $salt
     * @return String
     */
    public static function passwordUsername($salt)
    {        
        return sha1('FZEFEZdslmiue'.self::SPECIFIC_SALT.'zefzfe0979'.$salt.'8IKpml558');
    }
    
    /**
     * Give back the hashed username
     * @param $username
     * @return String
     */
    public static function hashedUsername($username)
    {        
        return sha1('uDZIubnDZF'.$username.'DFZEAijfd546'.self::SPECIFIC_SALT.'vfDZA56ffe');
    }
    
    /**
     * Give back the token for a key file
     * @param $id the id of the key
     * @param $certificate true if certificate, false otherwise
     * @return String
     */
    public static function tokenKeyFile($id, $certificate)
    {        
        return sha1('F45zef69ef'.$certificate.'FZEFASA'.self::SPECIFIC_SALT.'FEibisqfsd!'.$id.'854fe9z8418fe');
    }
    
    /**
     * Give back the password for a key file
     * @param $id the id of the key
     * @return String
     */
    public static function passwordKeyFile($id)
    {        
        return sha1('fze584feGE9z658fe'.self::SPECIFIC_SALT.'g5g4er69g5r!'.$id.'7ze98FEez89ze');
    }
    
    /**
     * Give back the hashed id 
     * @param $id
     * @return String
     */
    public static function hashedId($id)
    {        
        return sha1('fsez9ef!'.$id.'gfEgfr569z6'.self::SPECIFIC_SALT.'cgr5g66EGF8');
    }
    
    /**
     * Give back the general hashed token for the url
     * @param $token
     * @return String
     */
    public static function tokenGeneralUrl($token)
    {        
        return sha1('FEZ5845fe'.$token.'FZE65fez'.self::SPECIFIC_SALT.'FE51ef');
    }
}

?>