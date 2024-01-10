<?php
require './actor_class.php';
require './db_inc.php';
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
session_start();
if (isset($_SESSION['actor']) && $_SESSION['actor']->isAuthenticated()) {
  $actor = $_SESSION['actor'];
  if ($actor->isAdmin()) {
    echo '<!DOCTYPE html>
<html>
<head>
<title>Antique Evaluations</title>
<link rel="stylesheet" type="text/css" href="style.css">
<body>
<div>
<h1>Admin Portal</h1>
<h2> Welcome ' . htmlspecialchars($actor->getEmail(), ENT_QUOTES, 'UTF-8') . '</h2>
<p><a href="logout.php">Logout</a></p>

  </div>
  <table>
  <thead>
  <tr>
  <th>Name</th>
  <th>Time</th>
  <th>Preferred Contact</th>
  <th>Telephone</th>
  <th>Email</th>
  <th>Details</th>
  <th>Image</th>
  </tr>
  </thead>
  <tbody id="tableBody">
  ';
    global $pdo;

    $sql = 'SELECT ER.UploadID, ER.UploadTime, ER.PreferredContact, ER.Details, A.ID, A.Name, A.TelephoneNumber, A.Email
        FROM EvaluationRequests ER
                 JOIN Actor A ON ER.ActorID = A.ID;';


    try {
      $stmt = $pdo->prepare($sql);
      $stmt->execute();

      //fetch all evaluation requests
      $evaluationRequests = $stmt->fetchAll(PDO::FETCH_ASSOC);

      if (count($evaluationRequests) > 0) {
        foreach ($evaluationRequests as $evaluationRequest) {
          if ($evaluationRequest['PreferredContact'] == 0) {
            $evaluationRequest['PreferredContact'] = 'Email';
          } else {
            $evaluationRequest['PreferredContact'] = 'Phone';
          }
          // Output each row as a table row
          echo '<tr>';
          echo '<td><div>' . htmlspecialchars($evaluationRequest['Name'], ENT_QUOTES, 'UTF-8') . '</div></td>';
          echo '<td><div>' . htmlspecialchars($evaluationRequest['UploadTime'], ENT_QUOTES, 'UTF-8') . '</div></td>';
          echo '<td><div>' . htmlspecialchars($evaluationRequest['PreferredContact'], ENT_QUOTES, 'UTF-8') . '</div></td>';
          echo '<td><div>' . htmlspecialchars($evaluationRequest['TelephoneNumber'], ENT_QUOTES, 'UTF-8') . '</div></td>';
          echo '<td><div>' . htmlspecialchars($evaluationRequest['Email'], ENT_QUOTES, 'UTF-8') . '</div></td>';
          echo '<td><div>' . htmlspecialchars($evaluationRequest['Details'], ENT_QUOTES, 'UTF-8') . '</div></td>';
          echo '<td><div><img src="./uploads/' . $evaluationRequest['UploadID'] . '" alt="Image" style="max-height: 300px;"></div></td>';
          echo '</tr>';
        }
      }
      echo '</tbody></table></body></html>';



    } catch (PDOException $e) {
      echo 'Error fetching evaluation requests';
    }

  } elseif ($actor->isAuthenticated()) {
    $requestForgeryToken = bin2hex(random_bytes(32));
    $_SESSION['requestToken'] = $requestForgeryToken;

    echo '<!DOCTYPE html>
          <html>
          <head>
            <title>Antique Evaluations</title>
            <link rel="stylesheet" type="text/css" href="style.css">
            <style>
            #details {
              width: 100%;
              box-sizing: border-box; 
            }
            </style>
        <script>
        function updateCharacterCount(){
        let details = document.getElementById("details");
        let detailsError = document.getElementById("detailsError");

        let remaining = 1000 - details.value.length;

        detailsError.textContent = remaining + " characters remaining";

        if (remaining < 0){
          detailsError.style.color = "red";
        }
        else{
          detailsError.style.color = "black";
        }
    }
      
        </script>
        </head>
<body>
<div>
<div>
<h1>LOGGED IN</h1>
<a href="logout.php" id="logout-link">Logout</a>
<h2> Welcome ' . htmlspecialchars($actor->getEmail(), ENT_QUOTES, 'UTF-8') . '</h2>
</div>
<pre>
<form action="requestEvaluation.php" method="post", enctype="multipart/form-data">
<h2>Request Evaluation</h2>
<label for="contactPreference">Contact Preference:</label>
<select name="contactPreference" id="contactPreference required">
<option value="email">Email</option>
<option value="phone">Phone</option>
</select>
<label for="details">Evaluation Details:</label>
<textarea id="details" name="details" rows="4" cols="50" oninput="updateCharacterCount()"></textarea>
<div id="detailsError"></div>
<label for="image">Upload an image (JPEG or PNG, max 2MB):</label>
<input type="file" name="image" id="image" accept="image/*" required>
<input type="hidden" name="requestToken" value="' . $requestForgeryToken . '">
<input type="submit" value="Submit">
</pre>
</form>
</div>
</body>
</html>';
  }
} else {
  header('Location: 404.html');
}
?>