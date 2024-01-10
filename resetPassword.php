<?php

include_once './db_inc.php';
include_once './actor_class.php';

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
session_start();

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve the passwords entered by the user
    $password = $_POST['textPassword'];
    $password2 = $_POST['textPassword2'];
    $securityAnswer = $_POST['textSecurityAnswer'];
    
    //check if token exists in session
    if (!isset($_SESSION['token'])) {
        echo '<p>Invalid token</p>';
        exit();
    }

    $token = $_SESSION['token'];

    
    $actor = new Actor();
    try 
    {
        $actor->resetPassword($token, $password, $password2, $securityAnswer);

    }
    catch (Exception $e)
    {
        echo $e->getMessage();
        die();
    }

    echo '<p>Password successfully changed.';
    echo '<br>';
    echo 'Go back to <a href="index.php">login</a> page.</p>';
}

elseif (isset($_GET['token'])) {
    $token = $_GET['token'];
    $_SESSION['token'] = $token;

    global $pdo;

    // Check if the token exists in the database
    $query = 'SELECT * FROM Actor WHERE (PasswordResetID = :token)';
    $values = array(':token' => $token);

    try {
        $res = $pdo->prepare($query);
        $res->execute($values);
    } catch (PDOException $e) {

        throw new Exception($e);
    }

    $row = $res->fetch(PDO::FETCH_ASSOC);

    if (!is_array($row)) {
        echo '<p>Invalid token<p>';
        exit();
    }

    if (!$token === $row['PasswordResetID']) {
        echo '<p>Invalid token</p>';
        exit();
    }

    $securityQuestion = $row['SecurityQuestion'];

    $question = match ($securityQuestion) {
        1 => 'What was the model of your first car?',
        2 => 'What was the name of your first school?',
        3 => 'What is your favourite colour?'
    };
    
    echo '
<html>
<head>
<script>
function checkPassword() {
    let password = document.getElementById("textPassword").value;
    let confirmPassword = document.getElementById("textPassword2").value;
    let valid = true;


    // Check if passwords match
    if (password !== confirmPassword) {
        document.getElementById("passwordError").innerHTML = "Passwords do not match";
        valid = false;
    } else {
        document.getElementById("passwordError").innerHTML = "";
    }

    // Check if the password meets the criteria (e.g., at least 8 characters long)
    if (password.length < 8) {
        document.getElementById("passwordLengthError").innerHTML = "Password must be at least 8 characters long";
        valid = false;
    } else {
        document.getElementById("passwordLengthError").innerHTML = "";
    }

    return valid;
}

document.addEventListener("DOMContentLoaded", function () {
    // Attach event listeners to the password input fields
    document.getElementById("textPassword").addEventListener("input", checkPassword);
    document.getElementById("textPassword2").addEventListener("input", checkPassword);
});
</script>
<link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
<div>
<h1>Enter New Passwords</h1>
<pre>
<form action="resetPassword.php" method="post", onsubmit="return checkPassword();" >
<label for="textPassword">Password:</label><input type="password" name="textPassword" id="textPassword"><br>
<span id="passwordLengthError" style="color: red;"></span><br>
<label for="textPassword2">Confirm Password:</label><input type="password" name="textPassword2" id="textPassword2"><br>
<span id="passwordError" style="color: red;"></span><br>
<label for="textSecurityAnswer">Security Question: ' . $question . '</label><br>
<input type="text" name="textSecurityAnswer" id="textSecurityAnswer"><br>
<input type="submit" value="Submit">
</pre>
</form>
<div>   
</body>
</html>';

} else {
    header('Location: index.php');
    exit();
}
?>