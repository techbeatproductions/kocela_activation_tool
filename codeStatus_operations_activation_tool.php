<?php
require 'kocela_activation_tool_db_config.php';

// Parse the JSON data from the request body
$inputJSON = file_get_contents('php://input');
$inputData = json_decode($inputJSON, true);

// RSA encryption and decryption functions
function rsaEncrypt($data, $publicKey)
{
    // Generate a random symmetric key
    $symmetricKey = openssl_random_pseudo_bytes(32);

    // Encrypt the data with the symmetric key (e.g., AES encryption)
    $encryptedData = openssl_encrypt($data, 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(16));

    // Encrypt the symmetric key with the public key
    openssl_public_encrypt($symmetricKey, $encryptedSymmetricKey, $publicKey);

    // Combine the encrypted data and the encrypted symmetric key
    $encryptedPayload = $encryptedSymmetricKey . $encryptedData;

    return base64_encode($encryptedPayload);
}

function rsaDecrypt($data, $privateKey)
{
    // Decode the base64-encoded data
    $encryptedPayload = base64_decode($data);

    // Split the encrypted payload into the encrypted symmetric key and data
    $encryptedSymmetricKey = substr($encryptedPayload, 0, 256);
    $encryptedData = substr($encryptedPayload, 256);

    // Decrypt the symmetric key with the private key
    openssl_private_decrypt($encryptedSymmetricKey, $symmetricKey, $privateKey);

    // Decrypt the data with the symmetric key
    $decryptedData = openssl_decrypt($encryptedData, 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(16));

    return $decryptedData;
}

// Public and private key file paths
$publicKeyPath = 'C:\MAMP\htdocs\kc_ios_public_key.pem';
$privateKeyPath = 'C:\MAMP\htdocs\kc_ios_private_key.pem';

// Check the HTTP request method
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Fetch all code statuses
    if (isset($_GET['action']) && $_GET['action'] === 'fetchAllCodeStatuses') {
        try {
            $stmt = $pdo->query("SELECT * FROM codeStatus");
            $codeStatuses = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Encrypt the response data
            $encryptedData = rsaEncrypt(json_encode($codeStatuses), file_get_contents($publicKeyPath));

            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["data" => ["unencryptedData" => $codeStatuses, "encryptedData" => $encryptedData]]);
        } catch (Exception $e) {
            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["error" => $e->getMessage()]);
        }
    }

    // Fetch a specific code status by codeStatusID
    elseif (isset($_GET['action']) && $_GET['action'] === 'fetchCodeStatus' && isset($_GET['codeStatusID'])) {
        $codeStatusID = $_GET['codeStatusID'];
        try {
            $stmt = $pdo->prepare("SELECT * FROM codeStatus WHERE codeStatusID = ?");
            $stmt->execute([$codeStatusID]);
            $codeStatus = $stmt->fetch(PDO::FETCH_ASSOC);

            // Encrypt the response data
            $encryptedData = rsaEncrypt(json_encode($codeStatus), file_get_contents($publicKeyPath));

            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["data" => ["unencryptedData" => $codeStatus, "encryptedData" => $encryptedData]]);
        } catch (Exception $e) {
            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Create a new code status
    if (isset($inputData['action']) && $inputData['action'] === 'createCodeStatus' && isset($inputData['codeStatusName'])) {
        try {
            $codeStatusName = $inputData['codeStatusName']; // You may want to add validation here

            // Insert the new code status into the database
            $stmt = $pdo->prepare("INSERT INTO codeStatus (codeStatusName) VALUES (?)");
            $stmt->execute([$codeStatusName]);
            $newCodeStatusID = $pdo->lastInsertId(); // Get the generated codeStatusID

            // Generate a random symmetric key
            $symmetricKey = openssl_random_pseudo_bytes(32);

            // Encrypt the data with the symmetric key (e.g., AES encryption)
            $encryptedData = openssl_encrypt(json_encode(["codeStatusID" => $newCodeStatusID]), 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(16));

            // Encrypt the symmetric key with the public key
            openssl_public_encrypt($symmetricKey, $encryptedSymmetricKey, file_get_contents($publicKeyPath));

            // Combine the encrypted data and the encrypted symmetric key
            $encryptedPayload = $encryptedSymmetricKey . $encryptedData;

            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["message" => "Code status created successfully", "encryptedData" => base64_encode($encryptedPayload)]);
        } catch (Exception $e) {
            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["error" => $e->getMessage()]);
        }
    }
    // Modify a code status by codeStatusID
    elseif (isset($inputData['action']) && $inputData['action'] === 'modifyCodeStatus' && isset($inputData['codeStatusID']) && isset($inputData['newCodeStatusName'])) {
        try {
            $codeStatusID = $inputData['codeStatusID'];
            $newCodeStatusName = $inputData['newCodeStatusName']; // You may want to add validation here

            // Generate a random symmetric key
            $symmetricKey = openssl_random_pseudo_bytes(32);

            // Encrypt the data with the symmetric key (e.g., AES encryption)
            $encryptedData = openssl_encrypt(json_encode(["codeStatusID" => $codeStatusID]), 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(16));

            // Encrypt the symmetric key with the public key
            openssl_public_encrypt($symmetricKey, $encryptedSymmetricKey, file_get_contents($publicKeyPath));

            // Combine the encrypted data and the encrypted symmetric key
            $encryptedPayload = $encryptedSymmetricKey . $encryptedData;

            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["message" => "Code status modified successfully", "encryptedData" => base64_encode($encryptedPayload)]);
        } catch (Exception $e) {
            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    // Delete a code status by codeStatusID
    if (isset($inputData['action']) && $inputData['action'] === 'deleteCodeStatus' && isset($inputData['codeStatusID'])) {
        try {
            $codeStatusID = $inputData['codeStatusID'];
            $stmt = $pdo->prepare("DELETE FROM codeStatus WHERE codeStatusID = ?");
            $stmt->execute([$codeStatusID]);

            // Generate a random symmetric key
            $symmetricKey = openssl_random_pseudo_bytes(32);

            // Encrypt the data with the symmetric key (e.g., AES encryption)
            $encryptedData = openssl_encrypt(json_encode(["codeStatusID" => $codeStatusID]), 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(16));

            // Encrypt the symmetric key with the public key
            openssl_public_encrypt($symmetricKey, $encryptedSymmetricKey, file_get_contents($publicKeyPath));

            // Combine the encrypted data and the encrypted symmetric key
            $encryptedPayload = $encryptedSymmetricKey . $encryptedData;

            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["message" => "Code status deleted successfully", "encryptedData" => base64_encode($encryptedPayload)]);
        } catch (Exception $e) {
            // Set JSON header
            header('Content-Type: application/json');

            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} else {
    // Set JSON header
    header('Content-Type: application/json');

    echo json_encode(["error" => "Invalid request method"]);
}
?>
