<?php
include_once './actor_class.php';
include_once './sendEmail.php';
include_once './db_inc.php';

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
session_start();

if (isset($_SESSION['actor'])) {
    if ($_SESSION['actor']->isAuthenticated()) {
        header('Location: home.php');
        die();
    }
}

$requestForgeryToken = bin2hex(random_bytes(32));
$_SESSION['requestToken'] = $requestForgeryToken;


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve the email entered by the user
    $email = $_POST['email'];
    $requestTokenPost = $_POST['requestToken'];
    $requestTokenSession = $_SESSION['requestToken'];

    //check if token exists in session
    if (!isset($_SESSION['requestToken'])) {
        echo '<p>Invalid token</p>';
        exit();
    }

    if ($requestTokenPost !== $requestTokenSession) {
        echo '<p>Invalid token</p>';
        exit();
    }

    $_SERVER['requestToken'] = null;

    // Check if the email exists in the database
    global $pdo;

    $email = filter_var(trim($email), FILTER_SANITIZE_EMAIL);

    $query = 'SELECT * FROM Actor WHERE (Email = :email)';


    $values = array(':email' => $email);

    try {
        $res = $pdo->prepare($query);
        $res->execute($values);
    } catch (PDOException $e) {

        throw new Exception($e);
    }

    $row = $res->fetch(PDO::FETCH_ASSOC);

    if (is_array($row)) {
        // Generate a random string
        $randomString = bin2hex(random_bytes(16));

        // Store the random string in the database
        $query = 'UPDATE Actor SET PasswordResetID = :token, PasswordResetTime = NOW() WHERE ID = :id';

        $values = array(':token' => $randomString, ':id' => $row['ID']);

        try {
            $res = $pdo->prepare($query);
            $res->execute($values);
        } catch (PDOException $e) {

            throw new Exception($e);
        }

        // Send an email to the user with a link to reset their password
        $subject = 'Password Reset';
        $message = 'Click the link below to reset your password: <br>';
        $message .= '<a href="http://localhost/cw/resetPassword.php?token=' . $randomString . '">Reset Password</a>';

        $es = new emailSender();
        $es->send($email, $row['Name'], $subject, $message);
    }


    $textToAdd = '<p> If the email exists in our database, you will receive an email with a link to reset your password. </p>';


}
?>

<!DOCTYPE html>
<html>

<head>
    <title>Forgot Password</title>
</head>
<link rel="stylesheet" type="text/css" href="style.css">

<body>
    <div id="form">
        <h1>Forgot Password</h1>
        <form method="POST" action="<?php echo $_SERVER['PHP_SELF']; ?>">
            <label for="email">Email:</label>
            <input type="text" id="email" name="email" required>
            <input type="submit" value="Reset Password">
            <input type="hidden" name="requestToken" value="<?php echo $requestForgeryToken; ?>">
            <?php
        // Check if $textToAdd is set and not empty before injecting into the div
        if (isset($textToAdd) && !empty($textToAdd)) {
            echo '<div id="result">' . $textToAdd . '</div>';
        }
        ?>
        </form>
        
    </div>
</body>

</html>