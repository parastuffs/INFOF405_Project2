<?php 
//Do we need to launch the $_SESSION? I don't think so there is only one admin and the $_SESSION brings some problems of security... We don't need that anyway for this small website.
include('src/ini.php');

function __autoload($className)
{
	require_once('src/php/'.$className.'.class.php');
}

//Just for the correction of basic errors (and they will be used furthermore)
$General = new General();
$Access = new Access();
$Communication = new Communication();
$Key = new Key();
$User = new User();
$Ini = new Ini();

$Ini->serverKeys();

//Some verifications
if(!isset($_GET['page']))
    $_GET['page'] = 'index';

//We check which page we have to display
$page = $_GET['page'];
if(!preg_match('#^[a-zA-Z0-9_]{1,25}$#', $page))
    exit('Wrong page...');

if(!file_exists('src/html/'.$page.'.php'))
    exit('Wrong page...');

$token = '';
if(isset($_GET['generalToken']))
    $token = $_GET['generalToken'];
    
//We check if the user has the rights to access to this page (with the general toke)
$vf = $Access->verificationValidToken($page, $token);
if($vf['resultState'] === false)    
    exit($vf['resultText']);
    
//We display it
include('src/html/include/head.html');
include('src/html/include/listing.html');
include('src/html/'.$page.'.php');
include('src/html/include/bottom.html');
    
?>