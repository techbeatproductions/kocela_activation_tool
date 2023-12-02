<?php
// Include the database configuration file
include 'kocela_activation_tool_db_config.php';

// Parse the JSON data from the request body
$inputJSON = file_get_contents('php://input');
$inputData = json_decode($inputJSON, true);

// Function to encrypt data with RSA public key
function encryptWithRSA($data, $publicKey)
{
    openssl_public_encrypt($data, $encrypted, $publicKey);
    return base64_encode($encrypted);
}

// Function to decrypt data with RSA private key
function decryptWithRSA($data, $privateKey, $passphrase = null)
{
    // Provide the passphrase if the private key is passphrase-protected
    $res = openssl_private_decrypt(base64_decode($data), $decrypted, $privateKey, OPENSSL_PKCS1_PADDING);

    return $res ? $decrypted : false;
}


// Read the private key
$privateKeyPath = 'C:/MAMP/htdocs/kc_ios_private_key.pem';


if (!file_exists($privateKeyPath)) {
    die("Private key file not found at: $privateKeyPath");
}

$privateKeyContent = file_get_contents($privateKeyPath);
if ($privateKeyContent === false) {
    die("Failed to read private key file at: $privateKeyPath");
}

// Pass the passphrase when getting the private key
$privateKey = openssl_pkey_get_private($privateKeyContent);

// Read the public key
$publicKeyPath = 'C:/MAMP/htdocs/kc_ios_public_key.pem';
if (!file_exists($publicKeyPath)) {
    die("Public key file not found at: $publicKeyPath");
}

$publicKeyContent = file_get_contents($publicKeyPath);
if ($publicKeyContent === false) {
    die("Failed to read public key file at: $publicKeyPath");
}

$publicKey = openssl_pkey_get_public($publicKeyContent);

// User login endpoint
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($inputData['action']) && $inputData['action'] === 'userLogin') {
    // Debugging: Log the raw input data received
    error_log("Received Raw Input Data for Login: " . print_r($inputData, true));

    // Update the keys to match the input data structure
    $decryptedUsername = $inputData['username'];
    $decryptedPassword = $inputData['password'];
    error_log("Decrypted Password for Login: " . print_r($decryptedPassword, true));

    // Query the database to validate the user's credentials and fetch role information
    $stmt = $pdo->prepare("SELECT u.userID, u.username, u.password, u.salt, r.roleID, r.roleName
                           FROM user_credentials u
                           INNER JOIN user ur ON u.userID = ur.userID
                           INNER JOIN role r ON ur.roleID = r.roleID
                           WHERE u.username = ?");
    $stmt->execute([$decryptedUsername]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
      // Debugging: Log the fetched user credentials
        error_log("Fetched User Credentials: " . print_r($user, true));

        error_log("Stored Password: " . $user['password']);
        error_log("Salt: " . $user['salt']);

        if ($decryptedPassword === $user['password']) {
            // Generate a session token (you may use a more secure method)
            $sessionToken = bin2hex(random_bytes(32));

            // Store the session token in the login_sessions table
            $stmt = $pdo->prepare("INSERT INTO login_sessions (userID, sessionToken) VALUES (?, ?)");
            $stmt->execute([$user['userID'], $sessionToken]);

            // Encrypt the response with the client's public key
            $encryptedResponse = [
                "status" => "success",
                "message" => "Login successful",
                "role" => $user['roleName'],
                "salutation" => "Welcome back $decryptedUsername",
                "sessionToken" => encryptWithRSA($sessionToken, $publicKey),


            ];

            // Debugging: Log the successful login and session token
            error_log("Login successful for user: " . $decryptedUsername);
            error_log("Session Token: " . $sessionToken);

            echo json_encode($encryptedResponse);
        } else {
            // Debugging: Log an error for an invalid password
            error_log("Invalid password for user: " . $decryptedUsername);
            echo json_encode(["status" => "failure", "error" => "Invalid password"]);
        }
    } else {
        // Include the provided username for debugging and clarity
        error_log("Invalid username: " . $decryptedUsername);
        echo json_encode(["status" => "failure", "error" => "Invalid username: " . $decryptedUsername]);
    }
}


// User logout endpoint
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($inputData['action']) && $inputData['action'] === 'userLogout') {
    // Debugging: Log the raw input data received for logout
    error_log("Received Raw Input Data for Logout: " . print_r($inputData, true));

    // Update to match the input data structure
    $encryptedSessionToken = $inputData['sessionToken'];

    // Decrypt the session token using RSA private key
    $decryptedSessionToken = decryptWithRSA($encryptedSessionToken, $privateKey, $passphrase);

    if ($decryptedSessionToken !== false) {
        // Query the login_sessions table to check if the decrypted session token exists
        $stmt = $pdo->prepare("SELECT * FROM login_sessions WHERE sessionToken = ?");
        $stmt->execute([$decryptedSessionToken]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($session) {
            // Perform logout logic (e.g., delete the session token from the database)

            // Delete the session token from the database
            $deleteStmt = $pdo->prepare("DELETE FROM login_sessions WHERE sessionToken = ?");
            $deleteStmt->execute([$decryptedSessionToken]);

            // Debugging: Log the successful logout
            error_log("Logout successful for session token: " . $decryptedSessionToken);

            echo json_encode(["status" => "success","message" => "Logout successful"]);
        } else {
            // Debugging: Log an error for an invalid session token
            error_log("Invalid session token for logout: " . $decryptedSessionToken);
            echo json_encode(["status" => "failure","error" => "Invalid session token"]);
        }
    } else {
        // Debugging: Log an error for decryption failure
        error_log("Failed to decrypt session token");
        echo json_encode(["status" => "failure","error" => "Failed to decrypt session token"]);
    }
}

?>
