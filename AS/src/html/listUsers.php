<?php 

//We take the information from the url
$npage=0;
if(isset($_GET['npage']))
    $npage = $_GET['npage'];

//We take the users of the corresponding page
$list = $Access->listAccessControl($npage);

if($list['resultState'] === false)
{
    echo '<span bgcolor=red>'.$list['resultText'].'</span><br/>';
}
else if(count($list['user']) == 0)
{
    echo 'There is no user in the db.';
}
else
{//We display the users
    echo '<table border="1"><caption>List of clients/users</caption>';
    echo '<tr>';
    echo '  <th>Id</th>';
    echo '  <th>Username</th>';
    echo '  <th>Access to WS1</th>';
    echo '  <th>Access to WS2</th>';
    echo '  <th>Current keys</th>';
    echo '<tr/>';
    
    foreach($list['user'] as $key => $value)
    {
        $accessWS1 = 'yes';
        if($list['user'][$key]['WS1'] === false)
            $accessWS1 = 'no';
        if($list['user'][$key]['WS2'] === false)
            $accessWS2 = 'no';
        $accessWS2 = 'yes';
        
        echo '<tr>';
        echo '  <td>'.htmlspecialchars($key).'</td>';
        echo '  <td>'.htmlspecialchars($list['user'][$key]['username']).'</td>';
        echo '  <td>'.$accessWS1.'</td>';
        echo '  <td>'.$accessWS2.'</td>';
        echo '  <td><a href="?page=manageUserKeys&id='.htmlspecialchars($key).'">Manage user keys</a></td>';
        echo '<tr/>';
    }
    
    echo '<table>';
    
    if($list['nbrPages'] > 0)
    {
        echo '<br/><br/>List of pages<br/>';
        for($i=0; $i <= $list['nbrPages']; $i++)
            echo '<a href="?page=listUsers&npage='.$i.'">page '.($i+1).'</a><br/>';
    }
}
?>