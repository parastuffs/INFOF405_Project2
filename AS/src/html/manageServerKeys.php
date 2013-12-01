<?php 
 
if(isset($_GET['id']))
    $id = $_GET['id'];

//We check if we have to revoke a key
if(isset($_GET['revokeSym']) && isset($_GET['id']))
{
    $res = $Key->revocationSymmetricKey($id, $_GET['revokeSym']);
    if($res['resultState'] === true)
        echo '<font color="green">'.$res['resultText'].'</font>';
    else
        echo '<font color="red">'.$res['resultText'].'</font>';
}
else if(isset($_GET['revokeAsym']) && isset($_GET['id']))
{   
    $res = $Key->revocationAsymmetricKey($id, $_GET['revokeAsym']);
    if($res['resultState'] === true)
    {
        echo '<font color="green">'.$res['resultText'].'</font><br/>';
        //We create new asymetric keys
        $keys = $Key->getNewAsymKey($id);
        
        //We just say that they're available below
        echo 'You can download the new keys below.<br/>';
        
    }
    else
    {
        echo '<font color="red">'.$res['resultText'].'</font>';      
    }
}

//We take the information about the server session keys
$list = array('WS1','WS2','AS');
foreach($list as $in => $server)
{
    $id = $server;
    $symKeys = $Key->displayUserKeys($server);
    echo '<strong>SERVER '.$server.'</strong><br/>';
    if($symKeys['resultState'] === true && count($symKeys['keys']) > 0)
    {        
        echo '<table border="1"><caption><strong>List of session keys for '.$server.'.</strong></caption>';
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
            $revoke = '<a href="?page=manageServerKeys&amp;generalToken='.$Access->getGeneralToken().'&amp;id='.htmlspecialchars($id).'&amp;revokeSym='.htmlspecialchars($key).'">Revoke the key</a>';
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
        echo 'There is no session key for this server.';
        echo '<br/>';
    }

    //We take the public key of the user (the private key is never stored in the db)
    $asymKey = $Key->getAsymKeysIn($id);
    echo '<strong>Public key:</strong> ';
    echo '<a href="'.$asymKey['link'].'" target="__blank">Click here to download it</a><br/>'; 
    echo '<strong>Certificate:</strong> ';
    echo '<a href="'.$asymKey['linkCertificate'].'" target="__blank">Click here to download it</a><br/>';
    
    echo '<a href="?page=manageServerKeys&amp;generalToken='.$Access->getGeneralToken().'&amp;id='.htmlspecialchars($id).'&amp;revokeAsym='.htmlspecialchars($asymKey['id']).'">Revoke asymmetric key and generate a new one.</a><br/><br/>';
}
?>