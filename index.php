<?php
require './actor_class.php';
require './db_inc.php';
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
// Start the session
session_start();

if (isset($_SESSION['actor']) && $_SESSION['actor']->isAuthenticated()) {
  header('Location: home.php');
  die();
}

$requestForgeryToken = bin2hex(random_bytes(32));
$_SESSION['requestToken'] = $requestForgeryToken;


?>

<!DOCTYPE html>
<html>

<head>
  <title>My Homepage</title>
  <link rel="stylesheet" type="text/css" href="style.css">
</head>

<body>
  <div>
    <h1>Welcome to Lovejoy's Antiques</h1>
    <div id="f">
      <form action="loginCheck.php" method="post">
        Email: <input type="text" name="textEmail"><br>
        <br />
        Password: <input type="password" name="textPassword"><br>
        <br />
        <input type="submit" value="login">
        <input type="hidden" name="requestToken" value="<?php echo $requestForgeryToken; ?>">
      </form>
    </div>
    <p> Forgot your password? Click <a href="forgotPassword.php">here</a> to reset your password.</p>
    <p> Not yet registered? Click <a href="register.php">here</a> to register.</p>
  </div>
</body>

</html>