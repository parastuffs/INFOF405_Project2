<?php 

if(!isset($_GET['id']))
{
    echo 'Wrong url';
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
    else if(isset($_GET['revokeAsym']) && $_GET['revokeAsym'] == 1)
    {   
        $res = $Key->revocationAsymmetricKey($id, $_GET['revokeSym']);
        if($res['resultState'] === true)
            echo '<span bgcolor=green>'.$res['resultText'].'</span>';
        else
            echo '<span bgcolor=red>'.$res['resultText'].'</span>';        
    }
    
    //We take the information about the user session keys
    $symKeys = $Access->displayUserKeys($id);
    if($symKeys['resultState'] === true)
    {        
        echo '<table border="1"><caption><strong>List of session keys.</strong></caption>';
        echo '<tr>';
        echo '  <th>Id</th>';
        echo '  <th>Originy</th>';
        echo '  <th>Destination</th>';
        echo '  <th>Creation date</th>';
        echo '  <th>Validity</th>';
        echo '  <th>Revoke</th>';
        echo '</tr>';
        
        foreach($symKeys['resultState'] as $key => $value)
        {
            $validity = 'Active';
            $revoke = '<a href="?page=manageUserKeys&id='.htmlspecialchars($id).'&revokeSym='.htmlspecialchars($key).'">Revoke the key</a>';
            if($symKeys['resultState'][$key]['validity'] != 1)
            {
                $validity = 'Disactived';
                $revoke = 'Already revoked';
            }            
            
            echo '<tr>';
            echo '  <td>'.htmlspecialchars($key).'</td>';
            echo '  <td>'.htmlspecialchars($symKeys['resultState'][$key]['origin']).'</td>';
            echo '  <td>'.htmlspecialchars($symKeys['resultState'][$key]['destination']).'</td>';
            echo '  <td>'.htmlspecialchars($symKeys['resultState'][$key]['creationDate']).'</td>';
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
    $asymKey = $Access->getAsymKeysIn('CL'.$id);
    echo '<strong>Public key:</strong> ';
    echo $asymKey['publicKey'];
    echo '<br/><strong>Private key:</strong>: The private key is never stored in the database. You must generate a new one if the client lost it.<br/>';
    echo '<a href="?page=manageUserKey&id='.htmlspecialchars($id).'&revokeAsym='.htmlspecialchars($asymKey['id']).'">Revoke asymmetric key and generate a new one.</a>';
} 
?>