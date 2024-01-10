<?php
require './utils.php';
require './db_inc.php';
require './sendEmail.php';


class Actor
{

	private $id;
	private $email;
	private $authenticated;
	private $twoFactorSent;
	private $admin;
	private $timeout;

	public function __construct()
	{
		$this->id = NULL;
		$this->name = NULL;
		$this->authenticated = FALSE;
		$this->twoFactorSent = FALSE;
		$this->timeout = 0;
	}

	public function register(string $name, string $passwd, string $passwd2, string $email, string $telephone, int $securityQuestion, string $securityAnswer, string $securityAnswerConfirm): int
	{
		global $pdo;

		$name = filter_var(trim($name), FILTER_SANITIZE_STRING);
		$passwd = filter_var(trim($passwd), FILTER_SANITIZE_STRING);
		$passwd2 = filter_var(trim($passwd2), FILTER_SANITIZE_STRING);
		$telephone = filter_var(trim($telephone), FILTER_SANITIZE_NUMBER_INT);
		$email = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
		$securityQuestion = filter_var(trim($securityQuestion), FILTER_SANITIZE_NUMBER_INT);
		$securityAnswer = filter_var(trim($securityAnswer), FILTER_SANITIZE_STRING);
		$securityAnswerConfirm = filter_var(trim($securityAnswerConfirm), FILTER_SANITIZE_STRING);


		if (!$this->validateName($name)) {
			throw new Exception('Invalid name');
		}

		if (!$this->validateEmail($email)) {
			throw new Exception('Invalid email');
		}

		if (!is_null($this->getIdFromEmail($email))) {
			throw new Exception('Email already exists');
		}

		if (!$this->validateTelephone($telephone)) {
			throw new Exception('Invalid telephone');
		}

		if (!$this->validatePassword($passwd)) {
			throw new Exception('Invalid password');
		}

		if (!$this->passwordsMatch($passwd, $passwd2)) {
			throw new Exception('Passwords do not match');
		}
		
		if ($securityQuestion < 1 || $securityQuestion > 3) {
			throw new Exception('Invalid security question');
		}

		if (!$this->validateSecurityAnswer($securityAnswer)) {
			throw new Exception('Invalid security answer');
		}

		if (!$this->securityAnswersMatch($securityAnswer, $securityAnswerConfirm)) {
			throw new Exception('Security answers do not match');
		}



		$uuid = generateUUID4();

		while ($this->Idexists($uuid)) { //check if uuid already exists in database, avoid collisions
			$uuid = generateUUID4();
		}

		$uuid = trim($uuid);

		$sql = 'INSERT INTO Actor (Name, HashedPassword, Email, TelephoneNumber, Admin, ID, SecurityQuestion, SecurityQuestionAnswer) VALUES (:name, :password, :email, :telephone, :admin, :id, :securityQuestion, :securityQuestionAnswer)';

		$password = password_hash($passwd, PASSWORD_DEFAULT);
		$securityQuestionAnswer = password_hash($securityAnswer, PASSWORD_DEFAULT);

		$values = array(':name' => $name, ':password' => $password, ':email' => $email, ':telephone' => $telephone, ':admin' => 0, ':id' => $uuid, ':securityQuestion' => $securityQuestion, ':securityQuestionAnswer' => $securityQuestionAnswer);

		try {
			$stmt = $pdo->prepare($sql);
			$stmt->execute($values);
		} catch (PDOException $e) {
			throw new Exception('Database error: ' . $e->getMessage()); //change to generic error later
		}

		return $pdo->lastInsertId();

	}

	/* Login with username and password */
	public function login(string $email, string $passwd): bool
	{

		global $pdo;


		$email = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
		$passwd = filter_var(trim($passwd), FILTER_SANITIZE_STRING);

		if (!$this->validateEmail($email)) {
			return FALSE;
		}


		if (!$this->validatePassword($passwd)) {
			return FALSE;
		}


		$query = 'SELECT * FROM Actor WHERE (Email = :email)';


		$values = array(':email' => $email);


		try {
			$res = $pdo->prepare($query);
			$res->execute($values);
		} catch (PDOException $e) {

			throw new Exception($e);
		}

		$row = $res->fetch(PDO::FETCH_ASSOC);

		//if an associated account is found
		if (is_array($row)) {
			$timeout = $this->actorLoginTimeout($row['ID']);
			if ($timeout > 0) {
				$this->timeout = $timeout;
				return FALSE;
			}
			if (password_verify($passwd, $row['HashedPassword'])) {

				$this->id = $row['ID'];
				$this->email = $email;
				if ($row['Admin'] == 1) {
					$this->admin = TRUE;
				} else {
					$this->admin = FALSE;
				}
				$this->startOTP();
				$this->resetFailedLogin($row['ID']);
				return TRUE;
			} else {
				$this->logFailedLogin($row['ID']);
				return FALSE;
			}
		}

		return FALSE;
	}

	public function startOTP()
	{
		global $pdo;

		$otp = generateOTP();
		$hashedOTP = password_hash($otp, PASSWORD_DEFAULT);

		$query = 'INSERT INTO OTP (HashedOTP, GeneratedTime, ActorID, SubmissionAttempts) VALUES (:otp, NOW(), :actorId, 0)';

		$values = array(':otp' => $hashedOTP, ':actorId' => $this->id);

		try {
			$res = $pdo->prepare($query);
			$res->execute($values);
		} catch (PDOException $e) {

			throw new Exception($e);
		}

		// Send an email to the user with the OTP
		$subject = 'Lovejoy Antiqes OTP';
		$message = 'Please enter the following OTP to login: <br>';
		$message .= $otp;

		$this->twoFactorSent = TRUE;
		$es = new emailSender();
		$es->send($this->email, 'User', $subject, $message);
	}

	public function submitOTP($otp)
	{
		global $pdo;

		$otp = filter_var(trim($otp), FILTER_SANITIZE_STRING);

		$query = 'SELECT * FROM OTP WHERE (ActorID = :actorId)';

		$values = array(':actorId' => $this->id);

		try {
			$res = $pdo->prepare($query);
			$res->execute($values);
		} catch (PDOException $e) {

			throw new Exception($e);
		}

		$row = $res->fetch(PDO::FETCH_ASSOC);

		if (is_array($row)) {
			if (password_verify($otp, $row['HashedOTP'])) {
				$this->authenticated = TRUE;
				$this->deleteOTP($row['ActorID']);
				$this->registerLoginSession();
				return TRUE;
			} else {
				$this->logFailedOTP($row['ActorID']);
				if ($row['SubmissionAttempts'] + 1 > 2) {
					$this->deleteOTP($row['ActorID']);
				}
				return FALSE;
			}
		}

		return FALSE;

	}

	private function deleteOTP($id): void
	{
		global $pdo;

		$query = 'DELETE FROM OTP WHERE ActorID = :id';

		$values = array(':id' => $id);

		try {
			$res = $pdo->prepare($query);
			$res->execute($values);
		} catch (PDOException $e) {

			throw new Exception($e);
		}
	}

	private function logFailedOTP($id)
	{
		global $pdo;

		$query = 'UPDATE OTP SET SubmissionAttempts = SubmissionAttempts + 1 WHERE ActorID = :id';

		$values = array(':id' => $id);

		try {
			$res = $pdo->prepare($query);
			$res->execute($values);
		} catch (PDOException $e) {

			throw new Exception($e);
		}
	}



	private function actorLoginTimeout($id): int
	{
		global $pdo;
		$maxAttempts = 3;
		$baseDelay = 5;

		$query = 'SELECT LoginAttempts, LastLoginAttempt FROM Actor WHERE ID = :id';
		$values = array(':id' => $id);

		try {
			$res = $pdo->prepare($query);
			$res->execute($values);
		} catch (PDOException $e) {

			throw new Exception($e);
		}

		$row = $res->fetch(PDO::FETCH_ASSOC);
		$loginAttempts = $row['LoginAttempts'];
		$lastLoginAttempt = $row['LastLoginAttempt'];


		if ($loginAttempts < $maxAttempts) {
			return 0;
		}

		$time = time() - strtotime($lastLoginAttempt);

		if ($loginAttempts >= $maxAttempts && $time < $baseDelay * pow(2, $loginAttempts)) {
			return $baseDelay * pow(2, $loginAttempts) - $time;
		}

		return 0;

	}

	private function logFailedLogin(string $id): void
	{
		global $pdo;

		$query = 'UPDATE Actor SET LoginAttempts = LoginAttempts + 1, LastLoginAttempt = NOW() WHERE ID = :id';

		$values = array(':id' => $id);

		try {
			$res = $pdo->prepare($query);
			$res->execute($values);
		} catch (PDOException $e) {

			throw new Exception($e);
		}
	}

	private function resetFailedLogin(string $id): void
	{
		global $pdo;

		$query = 'UPDATE Actor SET LoginAttempts = 0, LastLoginAttempt = NULL WHERE ID = :id';

		$values = array(':id' => $id);

		try {
			$res = $pdo->prepare($query);
			$res->execute($values);
		} catch (PDOException $e) {

			throw new Exception($e);
		}
	}

	/* Logout the current user */
	public function logout(): void
	{
		/* Global $pdo object */
		global $pdo;

		/* Check that a Session has been started */
		if (session_status() == PHP_SESSION_ACTIVE) {
			/* Delete the session from the database */
			$query = 'DELETE FROM ActorSessions WHERE SessionID = :sid';
			$values = array(':sid' => session_id());

			/* Execute the query */
			try {
				$res = $pdo->prepare($query);
				$res->execute($values);
			} catch (PDOException $e) {
				/* If there is a PDO exception, throw a standard exception */
				throw new Exception($e);
			}

			/* Unset the session variables */
			$_SESSION = array();

			/* Delete the session cookie */
			if (ini_get('session.use_cookies')) {
				$params = session_get_cookie_params();
				setcookie(session_name(), '', time() - 42000,
					$params['path'], $params['domain'],
					$params['secure'], $params['httponly']
				);
			}

			/* Finally, destroy the session */
			session_destroy();
		}
	}


	private function registerLoginSession(): void
	{
		/* Global $pdo object */
		global $pdo;

		/* Check that a Session has been started */
		if (session_status() == PHP_SESSION_ACTIVE) {

			$query = 'REPLACE INTO ActorSessions (SessionID, ActorID, LoginTime) VALUES (:sid, :accountId, NOW())';
			$values = array(':sid' => session_id(), ':accountId' => $this->id);

			/* Execute the query */
			try {
				$res = $pdo->prepare($query);
				$res->execute($values);
			} catch (PDOException $e) {
				/* If there is a PDO exception, throw a standard exception */
				throw new Exception($e);
			}
		}

	}

	public function resetPassword($token, $passwd, $passwd2, $securityAnswer)
	{
		global $pdo;

		$token = filter_var(trim($token), FILTER_SANITIZE_STRING);
		$passwd = filter_var(trim($passwd), FILTER_SANITIZE_STRING);
		$passwd2 = filter_var(trim($passwd2), FILTER_SANITIZE_STRING);
		$securityAnswer = filter_var(trim($securityAnswer), FILTER_SANITIZE_STRING);


		if (!$this->validatePassword($passwd)) {
			throw new Exception('Invalid password');
		}

		if (!$this->passwordsMatch($passwd, $passwd2)) {
			throw new Exception('Passwords do not match');
		}

		if (!$this->validateSecurityAnswer($securityAnswer)) {
			throw new Exception('Invalid security answer');
		}



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
			throw new Exception('Invalid token');
		}

		if (!$token === $row['PasswordResetID']) {
			throw new Exception('Invalid token');
		}

		if (!password_verify($securityAnswer, $row['SecurityQuestionAnswer'])) {
			throw new Exception('Invalid security answer');
		}

		$hash = password_hash($passwd, PASSWORD_DEFAULT);

		$query = 'UPDATE Actor SET HashedPassword = :hash, PasswordResetID = NULL, PasswordResetTime = NULL WHERE ID = :id';
		$values = array(':hash' => $hash, ':id' => $row['ID']);

		try {
			$res = $pdo->prepare($query);
			$res->execute($values);
		} catch (PDOException $e) {

			throw new Exception($e);
		}
	}


	private function validateName(string $name): bool
	{
		if (strlen($name) < 2) {

			return FALSE;
		}
		return TRUE;
	}

	private function validateEmail(string $email): bool
	{
		if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
			return FALSE;
		}

		return TRUE;
	}

	private function validateTelephone(string $telephone): bool
	{

		if (strlen($telephone) < 11 || strlen($telephone) >= 15) {
			return FALSE;
		}

		return TRUE;
	}

	private function validatePassword(string $passwd): bool
	{
		if (strlen($passwd) < 8) {
			return FALSE;
		}

		return TRUE;
	}

	private function passwordsMatch(string $passwd, string $passwd2): bool
	{
		if ($passwd !== $passwd2) {
			return FALSE;
		}

		return TRUE;
	}

	private function validateSecurityAnswer(string $securityAnswer): bool
	{
		if (strlen($securityAnswer) < 2) {
			return FALSE;
		}

		return TRUE;
	
	}

	private function securityAnswersMatch(string $securityAnswer, string $securityAnswerConfirm): bool
	{
		if ($securityAnswer !== $securityAnswerConfirm) {
			return FALSE;
		}

		return TRUE;
	}

	public function getIdFromEmail(string $email): ?string
	{
		global $pdo;

		$sql = 'SELECT ID FROM Actor WHERE Email = :email';

		$values = array(':email' => $email);

		try {
			$stmt = $pdo->prepare($sql);
			$stmt->execute($values);
		} catch (PDOException $e) {
			throw new Exception('Database error: ' . $e->getMessage()); //change to generic error later
		}

		$row = $stmt->fetch(PDO::FETCH_ASSOC);

		if ($row === FALSE) {
			return NULL;
		}

		return $row['ID'];
	}

	public function Idexists(string $id): bool
	{
		global $pdo;

		$sql = 'SELECT ID FROM Actor WHERE ID = :id';

		$values = array(':id' => $id);

		try {
			$stmt = $pdo->prepare($sql);
			$stmt->execute($values);
		} catch (PDOException $e) {
			throw new Exception('Database error: ' . $e->getMessage()); //change to generic error later
		}

		$row = $stmt->fetch(PDO::FETCH_ASSOC);

		if ($row === FALSE) {
			return FALSE;
		}

		return TRUE;
	}

	public function isAuthenticated(): bool
	{
		global $pdo;

		if (session_status() == PHP_SESSION_ACTIVE) {
			$query = 'SELECT * FROM ActorSessions WHERE SessionID = :sid';
			$values = array(':sid' => session_id());

			try {
				$res = $pdo->prepare($query);
				$res->execute($values);
			} catch (PDOException $e) {
				throw new Exception($e);
			}

			$row = $res->fetch(PDO::FETCH_ASSOC);

			if (is_array($row)) {
				return $this->authenticated;
			} else {
				return FALSE;
			}
		}

		return $this->authenticated;
	}

	public function getEmail(): ?string
	{
		return $this->email;
	}

	public function getID(): ?string
	{
		return $this->id;
	}

	public function isAdmin(): bool
	{
		return $this->admin;
	}

	public function isLocked(): bool
	{
		return $this->timeout > 0;
	}

	public function getTimeout(): int
	{
		return $this->timeout;
	}

	public function twoFactorSent(): bool
	{
		return $this->twoFactorSent;
	}



}