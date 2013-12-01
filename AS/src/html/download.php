<?php 

if(!isset($_GET['idKey']) || !isset($_GET['token']) || !isset($_GET['name']) || !isset($_GET['certificate']))
    exit('Wrong page...');

if($_GET['certificate'] == 1)
    $certificate = true;
else
    $certificate = false;
$upload = Download::getAsymKeyFile($_GET['idKey'], $_GET['token'], $_GET['name'], $certificate);

if($upload['resultState'] !== true)
    echo 'Problem: '.$upload['resultText'];
    
?>