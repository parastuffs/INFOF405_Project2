<?php 

//We take the information from the url
$npage=0;
if(isset($_GET['npage']))
    $npage = $_GET['npage'];

//We check if we have to change the rights to a client or to delete it
if(isset($_GET['type']) && isset($_GET['id']))
{
    if($_GET['type'] == 'Delete')
        $res = $User->deleteClient($_GET['id']);
    else if(($_GET['type'] == 'WS1' || $_GET['type'] == 'WS2')  && isset($_GET['choice']))
        $res = $Access->changeUserAccess($_GET['id'], $_GET['type'], $_GET['choice'] == 'yes');
    
    if(isset($res))
    {
        if($res['resultState'] === true)
            echo '<font color="green">'.htmlspecialchars($res['resultText']).'</font><br/>';
        else
            echo '<font color="red">'.htmlspecialchars($res['resultText']).'</font><br/><br/>';
    }
}
    
//We take the users of the corresponding page
$list = $Access->listAccessControl($npage);

if($list['resultState'] === false)
{
    echo '<font color="red">'.$list['resultText'].'</font><br/>';
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
    echo '  <th>Delete the client</th>';
    echo '</tr>';
    
    foreach($list['user'] as $key => $value)
    {
        $accessWS1 = 'yes';
        $urlchangeAccessWS1 = '<a href="?page=listUsers&amp;generalToken='.$Access->getGeneralToken().'&amp;type=WS1&amp;choice=no&amp;id=CL'.htmlspecialchars($key).'">Change to no</a>';
        $accessWS2 = 'yes';
        $urlchangeAccessWS2 = '<a href="?page=listUsers&amp;generalToken='.$Access->getGeneralToken().'&amp;type=WS2&amp;choice=no&amp;id=CL'.htmlspecialchars($key).'">Change to no</a>';
        
        if($list['user'][$key]['WS1'] === false)
        {
            $accessWS1 = 'no';
            $urlchangeAccessWS1 = '<a href="?page=listUsers&amp;generalToken='.$Access->getGeneralToken().'&amp;type=WS1&amp;choice=yes&amp;id=CL'.htmlspecialchars($key).'">Change to yes</a>';
        }
        
        if($list['user'][$key]['WS2'] === false)
        {
            $accessWS2 = 'no';
            $urlchangeAccessWS2 = '<a href="?page=listUsers&amp;generalToken='.$Access->getGeneralToken().'&amp;type=WS2&amp;choice=yes&amp;id=CL'.htmlspecialchars($key).'">Change to yes</a>';
        }
        
        $urlDelete = '<a href="?page=listUsers&amp;generalToken='.$Access->getGeneralToken().'&amp;type=Delete&amp;id=CL'.htmlspecialchars($key).'">Delete</a>';
        
        echo '<tr>';
        echo '  <td>'.htmlspecialchars($key).'</td>';
        echo '  <td>'.htmlspecialchars($list['user'][$key]['username']).'</td>';
        echo '  <td>'.$accessWS1.'<br/>'.$urlchangeAccessWS1.'</td>';
        echo '  <td>'.$accessWS2.'<br/>'.$urlchangeAccessWS2.'</td>';
        echo '  <td><a href="?page=manageUserKeys&amp;generalToken='.$Access->getGeneralToken().'&amp;id=CL'.urlencode($key).'">Manage user keys</a></td>';
        echo '  <td>'.$urlDelete.'</td>';
        echo '</tr>';
    }
    
    echo '<table>';
    
    if($list['nbrPages'] > 0)
    {
        echo '<br/><br/>List of pages<br/>';
        for($i=0; $i <= $list['nbrPages']; $i++)
            echo '<a href="?page=listUsers&amp;generalToken='.$Access->getGeneralToken().'&amp;npage='.$i.'">page '.($i+1).'</a><br/>';
    }
}
?>