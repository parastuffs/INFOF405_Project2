<?php 

if(!isset($_GET['id']))
{
    echo 'Wrong url<br/>';
}
else
{   
    $id = $_GET['id'];
    
    //We check if we have to revoke a key
    if(isset($_GET['revokeSym']))
    {
        $res = $Key->revocationSymmetricKey($id, $_GET['revokeSym']);
        if($res['resultState'] === true)
            echo '<span bgcolor=green>'.$res['resultText'].'</span>';
        else
            echo '<span bgcolor=red>'.$res['resultText'].'</span>';
    }
    else if(isset($_GET['revokeAsym']))
    {   
        $res = $Key->revocationAsymmetricKey($id, $_GET['revokeAsym']);
        if($res['resultState'] === true)
        {
            echo '<span bgcolor=green>'.$res['resultText'].'</span>';
            //We create new asymetric keys
            $keys = $Key->getNewAsymKey($id);
            
            //We display them
            echo '<br/><br/>Keys to give to this client<br/>';
            echo '<strong>Public key:</strong> '.$keys['publicKey'].'<br/>';
            echo '<strong>Private key:</strong> '.$keys['privateKey'].'<br/><br/>';        
        }
        else
        {
            echo '<span bgcolor=red>'.$res['resultText'].'</span>';      
        }
    }
    
    //We take the information about the user session keys
    $symKeys = $Key->displayUserKeys($id);
    if($symKeys['resultState'] === true && count($symKeys['keys']) > 0)
    {        
        echo '<table border="1"><caption><strong>List of session keys.</strong></caption>';
        echo '<tr>';
        echo '  <th>Id</th>';
        echo '  <th>Origin</th>';
        echo '  <th>Destination</th>';
        echo '  <th>Creation date</th>';
        echo '  <th>Validity</th>';
        echo '  <th>Revoke</th>';
        echo '</tr>';
        
        foreach($symKeys['keys'] as $key => $value)
        {
            $validity = 'Active';
            $revoke = '<a href="?page=manageUserKeys&amp;id='.htmlspecialchars($id).'&amp;revokeSym='.htmlspecialchars($key).'">Revoke the key</a>';
            if($symKeys['keys'][$key]['validity'] != 1)
            {
                $validity = 'Disactived';
                $revoke = 'Already revoked';
            }            
            
            echo '<tr>';
            echo '  <td>'.htmlspecialchars($key).'</td>';
            echo '  <td>'.htmlspecialchars($symKeys['keys'][$key]['origin']).'</td>';
            echo '  <td>'.htmlspecialchars($symKeys['keys'][$key]['destination']).'</td>';
            echo '  <td>'.htmlspecialchars($symKeys['keys'][$key]['creationDate']).'</td>';
            echo '  <td>'.$validity.'</td>';
            echo '  <td>'.$revoke.'</td>';
            echo '</tr>';
        }
        echo '<br/>';
    }
    else
    {
        echo 'There is no session key for this user.';
        echo '<br/>';
    }
    
    //We take the public key of the user (the private key is never stored in the db)
    $asymKey = $Key->getAsymKeysIn($id);
    echo '<strong>Public key:</strong> ';
    echo $asymKey['publicKey'];
    echo '<br/><strong>Private key:</strong>: The private key is never stored in the database. You must generate a new one if the client lost it.<br/>';
    echo '<a href="?page=manageUserKeys&amp;id='.htmlspecialchars($id).'&amp;revokeAsym='.htmlspecialchars($asymKey['id']).'">Revoke asymmetric key and generate a new one.</a>';
} 
?>