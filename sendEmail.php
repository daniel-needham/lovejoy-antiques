<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

require './PHPMailer-master/src/Exception.php';
require './PHPMailer-master/src/PHPMailer.php';
require './PHPMailer-master/src/SMTP.php';

class emailSender {

    private $smtpUsername;
    private $smtpPassword;
    private $emailFrom;
    private $emailFromName;

    public function __construct()
    {
        $this->smtpUsername = "danielneedhamdn@gmail.com";
        $this->smtpPassword  = "hp1m8gZV2Fq6AIvz";
        $this->emailFrom  = "danielneedhamdn@gmail.com";
        $this->emailFromName  = "Lovejoy";
    }

 public function send($email, $name, $subject, $body)
{


    $mail = new PHPMailer;
    $mail->isSMTP();
    $mail->SMTPDebug = 0; // 0 = off (for production use) - 1 = client messages - 2 = client and server messages
    $mail->Host = "smtp-relay.brevo.com"; // use $mail->Host = gethostbyname('smtp.gmail.com'); // if your network does not support SMTP over IPv6
    $mail->Port = 587; // TLS only
    $mail->SMTPSecure = 'tls'; // ssl is depracated
    $mail->SMTPAuth = true;
    $mail->Username = $this->smtpUsername;
    $mail->Password = $this->smtpPassword;
    $mail->setFrom($this->emailFrom, $this->emailFromName);
    $mail->addAddress($email, $name);
    $mail->Subject = $subject;
    $mail->msgHTML($body); //$mail->msgHTML(file_get_contents('contents.html'), __DIR__); //Read an HTML message body from an external file, convert referenced images to embedded,
    $mail->AltBody = 'HTML messaging not supported';
    // $mail->addAttachment('images/phpmailer_mini.png'); //Attach an image file

    $mail->send();

}

}

?>