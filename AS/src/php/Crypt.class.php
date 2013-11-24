<?php 

class Crypt extends Database
{

    /**
     * Allows to crypt the information with a given password 
     * @param $text the text to encrypt
     * @param $password the password
     * @return String (the encrypted text)
     */
    public static function encrypt($text, $password)
    {
        
    }
    
    /**
     * Allows to decrypt an encrypted text
     * @param $text the text to decrypt
     * @param $password the password
     * @return String (the decrypted text)
     */
    public static function decrypt($text, $password)
    {
     
    }
    
    /** 
     * Check if we can take the specified algorithm on this server
     * @param $algo the name of the algorithm
     * @return boolean
     */
    public static function checkAlgo($algo)
    {
    
    }
}

?>