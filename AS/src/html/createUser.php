<?php 

//This page creates a new user.

//We check if we have the information
if(isset($_POST['name']) && isset($_POST['accessWS1']) && isset($_POST['accessWS2']))
{//If we have some information it means the admin just loaded the page again after entering the information of the new user to create
    $access = array('WS1'=>($_POST['accessWS1'] == '1'),'WS2'=>($_POST['accessWS2'] == '1'));
    $newUser = $User->insertNewClient($_POST['name'], $access);
    
    //If the user was successfully created, we create its RSA key and things like that
    if($newUser['resultState'] === true)
    {    
        echo '<span bgcolor="green">'.htmlspecialchars($newUser['resultText']).'</span><br/>';
        
        //We create the RSA keys (they're automatically created in this method)
        $keys = $Key->getAsymKeysIn('CL'.$newUser['id']);
        
        //We display them
        echo 'Keys to give to this client<br/>';
        echo '<strong>Public key:</strong> '.$keys['publicKey'].'<br/>';
        echo '<strong>Private key:</strong> '.$keys['privateKey'].'<br/>';
    }
    else
    {//We just display the error
        echo '<span bgcolor="red">'.htmlspecialchars($newUser['resultText']).'</span><br/>';
    }
}


?>

<strong>Complete the following information to create a new user</strong><br/>
<form action="?page=createUser" method="post">
    <label for="name">
        <span title="between 1 and 25 characters (a-zA-Z0-9._-)">Username:</span>
        <input type="text" id="name" name="name" maxlength="15">
    </label>
    <br/>
    Rights to access to the WS1:
    <select name="accessWS1" size="1">
        <option value="1">yes
        <option value="2">no
    </select>
    <br/>
    Rights to access to the WS2:
    <select name="accessWS2" size="1">
        <option value="1">yes
        <option value="2">no
    </select>
    <br/>
    <input type="submit" value="Create the new user"><br>
</form>