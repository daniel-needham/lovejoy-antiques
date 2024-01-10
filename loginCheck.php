<?php
require './actor_class.php';
require './db_inc.php';

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
session_start();

if(!$_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Location: index.php');
    die();

}

//values from webform
$email = $_POST['textEmail'];
$password = $_POST['textPassword'];
$requestTokenPost = $_POST['requestToken'];
$requestTokenSession = $_SESSION['requestToken'];

//check if token exists in session
if (!isset($_SESSION['requestToken'])) {
    echo '<p>Invalid token</p>';
    exit();
}

if ($requestTokenPost !== $requestTokenSession){
    echo '<p>Invalid token</p>';
    exit();

}

$_SERVER['requestToken'] = null;

//create actor object
$actor = new Actor();
try 
{
    $newID = $actor->login($email, $password);

}
catch (Exception $e)
{
    echo $e->getMessage();
    die();
}

if ($actor->twoFactorSent())
{
    $_SESSION['actor'] = $actor;
    header('Location: OTP.php');
}
elseif ($actor->isLocked())
{   
    echo '<p>Your account is locked for ' . htmlspecialchars($actor->getTimeout(), ENT_QUOTES, 'UTF-8') . ' seconds. Please contact the administrator.';
    echo '<br>';
    echo 'Go back to <a href="index.php">login</a> page.</p>';
} else
{
    echo '<p>Email or password is incorrect';
    echo '<br>';
    echo 'Forgot your password? Click <a href="forgotPassword.php">here</a> to reset your password.';
    echo '<br>';
    echo 'Go back to <a href="index.php">login</a> page.<p>';
}
?>