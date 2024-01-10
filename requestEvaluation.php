<?php
require './actor_class.php';
require './db_inc.php';
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
session_start();

function storeImageUploadDetailsToDB($fileName, $actorId, $preferredContact, $details)
{
    global $pdo;

    $sql = 'INSERT INTO EvaluationRequests (UploadID, ActorID, UploadTime, PreferredContact, Details) VALUES (:uploadId, :actorId, NOW(), :preferredContact, :details)';

    $values = array(':uploadId' => $fileName, ':actorId' => $actorId, ':preferredContact' => $preferredContact, ':details' => $details);

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($values);
        return true;
    } catch (PDOException $e) {
        return false;
    }

}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_SESSION['actor']) && $_SESSION['actor']->isAuthenticated()) {

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

    // Maximum allowed file size (2MB)
    $maxFileSize = 2 * 1024 * 1024;  // 2MB in bytes

    // Allowed file extensions
    $allowedExtensions = ['jpeg', 'jpg', 'png'];

    // File upload path
    $targetDir = "uploads/";

    // Check if the file field is set in the POST request
    if (isset($_FILES["image"])) {
        $uploadedFile = $_FILES["image"];

        // Check file size
        if ($uploadedFile["size"] > $maxFileSize) {
            echo "Error: File size exceeds the allowed limit (2MB).";
            exit();
        }

        // Check file extension
        $fileExtension = strtolower(pathinfo($uploadedFile["name"], PATHINFO_EXTENSION));
        if (!in_array($fileExtension, $allowedExtensions)) {
            echo "Error: Invalid file extension. Only JPEG and PNG are allowed.";
            exit();
        }

        // Convert contact preference to boolean
        // 0 = email, 1 = phone
        $contactPreference = $_POST['contactPreference'] === 'email' ? 0 : 1;

        // Get the evaluation details
        $details = $_POST['details'];
        if (strlen($details) > 1000) {
            echo "Error: Evaluation details must be less than 1000 characters.";
            exit();
        }

        $details = filter_var(trim($details), FILTER_SANITIZE_STRING);

        // Generate a unique name for the uploaded file
        $fileName = uniqid('upload_', true);
        $fileNameWithExtension = $fileName . '.' . $fileExtension;
        $targetFile = './' . $targetDir . $fileName . '.' . $fileExtension;

        // Get the actor ID from the session
        $actorId = $_SESSION['actor']->getID();

        if (move_uploaded_file($uploadedFile["tmp_name"], $targetFile) && storeImageUploadDetailsToDB($fileNameWithExtension, $actorId, $contactPreference, $details)) {
            echo "The file has been uploaded successfully.";
        } else {
            echo "Error uploading the file.";
        }
    } else {
        echo "Error: File field not set in the POST request.";
    }
    echo "<br>";
    echo "<a href='home.php'>Return to Home</a>";
} else {
    header('Location: 404.html');
}


?>