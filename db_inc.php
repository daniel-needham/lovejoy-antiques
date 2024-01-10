<?php
$host = 'localhost';
$user = 'LoginApp';
$passwd = 'password';
$schema = 'ComputerSecurity';
$pdo = NULL;
$dsn = 'mysql:host=' . $host . ';dbname=' . $schema;
try
{  
   /* PDO object creation */
   $pdo = new PDO($dsn, $user,  $passwd);
   
   /* Enable exceptions on errors */
   $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
}
catch (PDOException $e)
{
   /* If there is an error an exception is thrown */
   echo 'Database connection failed.';
   die();
}