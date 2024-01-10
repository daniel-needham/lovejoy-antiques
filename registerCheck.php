<?php
require './actor_class.php';
require './db_inc.php';

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
session_start();

//values from webform
$name = $_POST['textName'];
$passwd = $_POST['textPassword'];
$passwd2 = $_POST['textPassword2'];
$telephone = $_POST['textTelephone'];
$email = $_POST['textEmail'];
$securityQuestion = $_POST['securityQuestion'];
$securityAnswer = $_POST['textSecurityAnswer'];
$securityAnswerConfirm = $_POST['textSecurityAnswerConfirm'];
$requestTokenPost = $_POST['requestToken'];

$requestTokenSession = $_SESSION['requestToken'];


//check if token exists in session
if (!isset($_SESSION['requestToken'])) {
    echo '<p>Invalid token</p>';
    exit();
}

if ($requestTokenPost !== $requestTokenSession){
    echo '<p>Invalid token not same</p>';
    exit();

}

$_SERVER['requestToken'] = null;

try {
    //create actor object
    $actor = new Actor();
    $message = '<p>Registration successful<p><br><p>Go back to <a href="index.php">login</a> page.</p>';
    $newID = $actor->register($name, $passwd, $passwd2, $email, $telephone, $securityQuestion, $securityAnswer, $securityAnswerConfirm);

} catch (Exception $e) {
    $message = $e->getMessage();
}

?>

<!DOCTYPE html>
<html>

<head>
    <title>Lovejoy Antiques</title>
    <link rel="stylesheet" type="text/css" href="style.css">
</head>

<body>
    <div>
        <pre>
            <?php echo $message; ?>
        </pre>
    </div>
</body>