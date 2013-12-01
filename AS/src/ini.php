<?php 
//Creation of .htaccess & .htpassword file
if(!file_exists('.htaccess'))
{
    //We ask for a password if nothing was given
    if(!isset($_POST['name']) || !isset($_POST['pass']))
    {
        echo '<strong>Define a username and a password for the admin section.</strong><br/><br/>
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
            $path = implode('/',$inf);
        }
        else
        {//windows
            $path = explode('\\',$path);   
            array_pop($path);     
            $path = implode('\\',$path);
        }
        $fic = fopen('.htaccess','w');
        fputs($fic, 'AuthName "Administration: see readme.txt"
                    AuthType Basic
                    AuthUserFile "'.$path.'\.htpasswd"
                    Require valid-user');
        fclose($fic);
        
        //We create the htpassword
        $fic = fopen('.htpasswd','w');
        fputs($fic, $_POST['name'].':'.crypt($_POST['pass']));
        fclose($fic);
        
        //redirection
        header('Location: index.php?page=index');
        exit();
    }    
}

?>