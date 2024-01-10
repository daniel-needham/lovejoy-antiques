<?php
require './actor_class.php';
require './db_inc.php';
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");

session_start();

$actor = $_SESSION['actor'];

if ($actor->isAuthenticated())
{
    $actor->logout();
    //redirect to index.php
    header('Location: index.php');
}
else
{
    echo 'Logout failed';
    echo '<br>';
    echo 'Go back to <a href="index.php">home</a> page.';
}
?>