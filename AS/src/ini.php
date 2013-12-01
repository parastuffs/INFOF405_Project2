<?php 
//Creation of .htaccess & .htpassword file
if(!file_exists('.htaccess'))
{
    $formulaire = true;
    if(isset($_POST['name']) && isset($_POST['pass']))
    {
        if(preg_match('#^[a-zA-Z]{1,25}$#',$_POST['name']) && preg_match('#^.{1,50}$#',$_POST['pass']))
            $formulaire = false;
            
        if($formulaire === true)
            echo 'Give a valid username (a-zA-Z, minimum 1 character, maximum 25) and password (minimum 1 character, maximum 50) please.<br/><br/>';
    }
    
    //We ask for a password if nothing was given
    if($formulaire === true)
    {
        echo '
        Hello! Welcome in this webinterface made for the project INFO-F405!<br/>
        Please, be sure that:<br/>
         - The repository for this website has the rights to create and destroy files.<br/>
         - You have already installed the database with the query in the file "info405.sql".<br/>
         - You have specified the right username and password for the database access in the file AS/src/php/General.class.php.<br/>
         - You have activated the https for this website (cf. report).<br/>
         - You have activated the open_ssl module in wamp.<br/>
        <br/>
        <strong>Define a username and a password for the admin section.</strong><br/><br/>
        After that, if you have problem with the authentification (like it keeps asking a password), <br/>
        be sure that your Apache server use the crypt() function into the .htpasswd file (httpd.conf). <br/>
        If there is still a problem, remplace your login directly into the .htpasswd file without crypting it. <br/> 
        There are sometimes some problems with WampServer that wouldn\'t appear on real servers.<br/><br/>
        <form method="post">
        <p>
            Username : <input type="text" name="name"><br/>
            Password : <input type="text" name="pass"><br/>        
            <input type="submit" value="Create the account">
        </p>
        </form>';

                
        exit();        
    }
    else
    {
        //We create the htaccess
        $path = realpath('index.php');
        $inf = explode('/',$path);
        
        if(isset($inf[1]))
        {//linux
            array_pop($inf);     
            $path = implode('/',$inf).'/';
        }
        else
        {//windows
            $path = explode('\\',$path);   
            array_pop($path);     
            $path = implode('\\',$path).'\\';
        }        
        $fic = fopen('.htaccess','w');
        fputs($fic, 'AuthName "Administration: see readme.txt"
                    AuthType Basic
                    AuthUserFile "'.$path.'.htpasswd"
                    Require valid-user');
        fclose($fic);
        
        //We create the htpassword
        $fic = fopen('.htpasswd','w');
        fputs($fic, $_POST['name'].':'.crypt($_POST['pass']));
        fclose($fic);
        
        //We generate a new special salt for the website, to avoid the "sécurité par l'aveugle"
        $t = file_get_contents('src/php/Crypt.class.php');
        $crypto = true;
        $bytes = openssl_random_pseudo_bytes(25, $crypto);        
        $pass = sha1(bin2hex($bytes));
        $t = preg_replace('#(const SPECIFIC_SALT) \\= "([a-zA-Z0-9]{40})";#','$1 = "'.$pass.'";',$t);
        $fic = fopen('src/php/Crypt.class.php','w');
        fputs($fic, $t);
        fclose($fic);
        
        //redirection
        header('Location: index.php?page=index');
        exit();
    }    
}

?>