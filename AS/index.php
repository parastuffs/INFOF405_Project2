<?php 

function __autoload($className)
{
	require_once('src/php/'.$className.'.class.php');
}

//Just for the correction of basic errors
$General = new General();
$access = new Access();
$communication = new Communication();
$key = new Key();
$User = new User();

?>