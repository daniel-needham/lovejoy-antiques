<?php
require './actor_class.php';
require './db_inc.php';

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
session_start();

if (!isset($_SESSION['actor']) || !$_SESSION['actor']->twoFactorSent()) {
  header('Location: index.php');
  die();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

  if (!isset($_SESSION['requestToken'])) {
    echo '<p>Invalid token</p>';
    exit();
  }

  if ($_POST['requestToken'] !== $_SESSION['requestToken']) {
    echo '<p>Invalid token</p>';
    exit();
  }

  $_SESSION['requestToken'] = null;

  
  $otp = $_POST['otp'];
  $actor = $_SESSION['actor'];
  try {
    $actor->submitOTP($otp);
  } catch (Exception $e) {
    echo $e->getMessage();
    die();
  }

  if ($actor->isAuthenticated()) {
    header('Location: home.php');
    die();
  } else {
    echo 'OTP is incorrect or has expired';
    echo '<br>';
    echo '<a href="OTP.php">Try again</a> or go back to <a href="index.php">login</a> page.';
    die();
  }
}

$requestForgeryToken = bin2hex(random_bytes(32));
$_SESSION['requestToken'] = $requestForgeryToken;

?>

<!DOCTYPE html>
<html>

<head>
  <title>Lovejoy Antiques</title>
  <link rel="stylesheet" type="text/css" href="style.css">
</head>

<body>
  <div>
    <h1>Submit OTP</h1>
    <p>A one-time password has been sent to your email. Please enter the OTP below.</p>
    <p>Didn't receive the OTP? Click <a href="index.php">here</a> to go back to the login page.</p>
    <div id="f">
      <form action="OTP.php" method="post">
        <label for="otp">OTP:</label><input type="password" name="otp"><br>
        <input type="hidden" name="requestToken" value="<?php echo $requestForgeryToken; ?>">
        <br />
        <input type="submit" value="Submit">
      </form>
    </div>
  </div>
</body>

</html>