<?php
// ----- CONFIG -----
$config['server_core'] = 5; // CMaNGOS Classic
$dbHost = 'localhost';
$dbName = 'classicrealmd';
$dbUser = 'dbuser';
$dbPass = 'dbpass';

// Enable GMP Extension
if (!extension_loaded('gmp')) {
    die("GMP extension is not loaded.");
}

// DB connection
$pdo = new PDO("mysql:host=$dbHost;dbname=$dbName", $dbUser, $dbPass);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Form
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
?>
    <form method="POST">
        Username: <input type="text" name="username" required><br>
        Email: <input type="email" name="email" required><br>
        Password: <input type="password" name="password" required><br>
        Confirm Password: <input type="password" name="repassword" required><br>
        <input type="submit" name="submit" value="register">
    </form>
<?php
    exit;
}

// Input
$username = strtoupper(trim($_POST['username']));
$email = strtoupper(trim($_POST['email']));
$password = $_POST['password'];
$repassword = $_POST['repassword'];

// Validation
if (!preg_match('/^[0-9A-Z-_]+$/', $username)) {
    die("Invalid username.");
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("Invalid email.");
}
if ($password !== $repassword) {
    die("Passwords do not match.");
}
if (strlen($password) < 4 || strlen($password) > 16) {
    die("Password must be 4–16 characters.");
}
if (strlen($username) < 2 || strlen($username) > 16) {
    die("Username must be 2–16 characters.");
}

// Duplicate check
$stmt = $pdo->prepare("SELECT id FROM account WHERE username = ?");
$stmt->execute([$username]);
if ($stmt->fetch()) {
    die("Username already exists.");
}

// SRP6 Registration
list($salt, $verifier) = getRegistrationData($username, $password);

// DB insert (s = salt, v = verifier)
$stmt = $pdo->prepare("INSERT INTO account (username, s, v, email, expansion) VALUES (?, ?, ?, ?, ?)");
$stmt->execute([$username, $salt, $verifier, $email, 1]);

echo "Account created successfully!";


// ---------- SRP6 FUNCTIONS ----------

function getRegistrationData($username, $password) {
    global $config;

    $salt = random_bytes(32);
    $verifier = calculateSRP6Verifier($username, $password, $salt);

    if ($config['server_core'] === 5) {
        $salt = strtoupper(bin2hex($salt));                 // s = hex string
        $verifier = strtoupper(bin2hex(strrev($verifier))); // v = reversed hex string
    } else {
        $salt = strtoupper(bin2hex($salt));
        $verifier = strtoupper(bin2hex($verifier));
    }

    return [$salt, $verifier];
}

function calculateSRP6Verifier($username, $password, $salt) {
    global $config;

    $g = gmp_init(7);
    $N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);

    $h1 = sha1(strtoupper($username . ':' . $password), true);

    if ($config['server_core'] === 5) {
        $h2 = sha1(strrev($salt) . $h1, true); // CMaNGOS-specific
    } else {
        $h2 = sha1($salt . $h1, true);
    }

    $h2Int = gmp_import($h2, 1, GMP_LSW_FIRST);
    $verifier = gmp_powm($g, $h2Int, $N);
    $verifierBytes = gmp_export($verifier, 1, GMP_LSW_FIRST);
    $verifierBytes = str_pad($verifierBytes, 32, chr(0), STR_PAD_RIGHT);

    return $verifierBytes;
}
?>
