<?php
session_start();
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");

$requestForgeryToken = bin2hex(random_bytes(32));
$_SESSION['requestToken'] = $requestForgeryToken;

echo '
<html>
<head>
<script>
function checkPassword() {
    let password = document.getElementById("textPassword").value;
    let confirmPassword = document.getElementById("textPassword2").value;
    let securityAnswer = document.getElementById("textSecurityAnswer").value;
    let securityAnswerConfirm = document.getElementById("textSecurityAnswerConfirm").value;
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

    // Check if security questions match
    if (securityAnswer !== securityAnswerConfirm) {
        document.getElementById("securityAnswerError").innerHTML = "Security answers do not match";
        valid = false;
    } else {
        document.getElementById("securityAnswerError").innerHTML = "";
    }

    return valid;
}

document.addEventListener("DOMContentLoaded", function () {
    // Attach event listeners to the password input fields
    document.getElementById("textPassword").addEventListener("input", checkPassword);
    document.getElementById("textPassword2").addEventListener("input", checkPassword);
    document.getElementById("textSecurityAnswer").addEventListener("input", checkPassword);
    document.getElementById("textSecurityAnswerConfirm").addEventListener("input", checkPassword);
});
</script>
<link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
<div>
<h1>Register</h1>
<div>
<pre>
<form action="registerCheck.php" method="post" onsubmit="return checkPassword();">
<label for="textName">Name:</label><input type="text" name="textName">
<label for="textEmail">Email:</label><input type="text" name="textEmail">
<label for="textTelephone">Telephone:</label><input type="text" name="textTelephone">
<label for="textPassword">Password:</label><input type="password" name="textPassword" id="textPassword">
<span id="passwordLengthError" style="color: red;"></span>
<label for="textPassword2">Confirm Password:</label><input type="password" name="textPassword2" id="textPassword2">
<span id="passwordError" style="color: red;"></span>
<label for="securityQuestion">Select a security question:</label>
<select name="securityQuestion" id="securityQuestion">
<option value="1">What was the model of your first car?</option>
<option value="2">What was the name of your first school?</option>
<option value="3">What is your favourite colour?</option>
</select>
<label for="securityAnswer">Security Answer:</label><input type="text" name="textSecurityAnswer" id="textSecurityAnswer">
<label for="securityAnswerConfirm">Confirm Security Answer:</label><input type="text" name="textSecurityAnswerConfirm" id="textSecurityAnswerConfirm">
<span id="securityAnswerError" style="color: red;"></span>
<input type="hidden" name="requestToken" value="' . $requestForgeryToken . '">
</pre>
<input type="submit" value="register">
</form>
</div>
</div>
</body>
</html>'
?>