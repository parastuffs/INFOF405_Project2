<?php 

class Crypt extends General
{
    const ALGO = 'rijndael-256';
    const MODE = 'cfb';
    
    /**
     * Allows to crypt the information with a given password 
     * @param $text the text to encrypt
     * @param $password the password
     * @return String (the encrypted text)
     */
    public static function encrypt($text, $password, $iv)
    {
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
     * Give back the encrypted id of a user 
     * @param $id int the initial id
     * @param $salt string the salt
     * @return String
     */
    public static function encryptId($id, $salt)
    {        
        return Cryptage::encrypt($id,'ezf45ç))à!è!à6zfSQfzef'.$salt.'lpfeziefz!à!èè!ç!');
    }
    
    
    /**
     * Give back the encrypted access to a WS 
     * @param $WS int the access to the website (1:allowed, 0:refused)
     * @param $salt string the salt
     * @return String
     */
    public static function encryptWS($WS, $salt)
    {        
        return Cryptage::encrypt($WS,'564zecv4zFEFEZf4fl'.$salt.'p^dz^l^p)àç!à!èç');
    }
}

?>