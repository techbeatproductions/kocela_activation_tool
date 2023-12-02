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
    $action = isset($_GET['action']) ? $_GET['action'] : '';

    // Fetch all statuses
    if ($action === 'fetchAllStatuses') {
        try {
            $stmt = $pdo->query("SELECT * FROM status");
            $statuses = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Encrypt the response data
            $encryptedData = rsaEncrypt(json_encode($statuses), file_get_contents($publicKeyPath));

            echo json_encode(["data" => ["unencryptedData" => $statuses, "encryptedData" => $encryptedData]]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    } elseif ($action === 'fetchStatus' && isset($_GET['statusID'])) {
        // Fetch a specific status by statusID
        $statusID = $_GET['statusID'];
        try {
            $stmt = $pdo->prepare("SELECT * FROM status WHERE statusID = ?");
            $stmt->execute([$statusID]);
            $status = $stmt->fetch(PDO::FETCH_ASSOC);

            // Encrypt the response data
            $encryptedData = rsaEncrypt(json_encode($status), file_get_contents($publicKeyPath));

            echo json_encode(["data" => ["unencryptedData" => $status, "encryptedData" => $encryptedData]]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Create a new status
    if (isset($inputData['action']) && $inputData['action'] === 'createStatus' && isset($inputData['statusName'])) {
        try {
            // Extract and sanitize the input data
            $statusName = htmlspecialchars($inputData['statusName']); // You may want to add more validation/sanitization here

            // Insert the new status into the status table
            $stmt = $pdo->prepare("INSERT INTO status (statusName) VALUES (:statusName)");
            $stmt->bindParam(':statusName', $statusName);
            $stmt->execute();

            // Get the newly inserted statusID
            $newStatusID = $pdo->lastInsertId();

            // Generate a random symmetric key
            $symmetricKey = openssl_random_pseudo_bytes(32);

            // Encrypt the data with the symmetric key (e.g., AES encryption)
            $encryptedData = openssl_encrypt(json_encode(["statusID" => $newStatusID]), 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(16));

            // Encrypt the symmetric key with the public key
            openssl_public_encrypt($symmetricKey, $encryptedSymmetricKey, file_get_contents($publicKeyPath));

            // Combine the encrypted data and the encrypted symmetric key
            $encryptedPayload = $encryptedSymmetricKey . $encryptedData;

            echo json_encode(["message" => "Status created successfully", "encryptedData" => base64_encode($encryptedPayload)]);
        } catch (PDOException $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    } elseif (isset($inputData['action']) && $inputData['action'] === 'modifyStatus' && isset($inputData['statusID']) && isset($inputData['newStatusName'])) {
        // Modify a status by statusID
        try {
            $statusID = $inputData['statusID'];
            $newStatusName = htmlspecialchars($inputData['newStatusName']); // You may want to add validation here

            // Update the status in the status table
            $stmt = $pdo->prepare("UPDATE status SET statusName = :newStatusName WHERE statusID = :statusID");
            $stmt->bindParam(':newStatusName', $newStatusName);
            $stmt->bindParam(':statusID', $statusID);
            $stmt->execute();

            // Generate a random symmetric key
            $symmetricKey = openssl_random_pseudo_bytes(32);

            // Encrypt the data with the symmetric key (e.g., AES encryption)
            $encryptedData = openssl_encrypt(json_encode(["statusID" => $statusID]), 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(16));

            // Encrypt the symmetric key with the public key
            openssl_public_encrypt($symmetricKey, $encryptedSymmetricKey, file_get_contents($publicKeyPath));

            // Combine the encrypted data and the encrypted symmetric key
            $encryptedPayload = $encryptedSymmetricKey . $encryptedData;

            echo json_encode(["message" => "Status modified successfully", "encryptedData" => base64_encode($encryptedPayload)]);
        } catch (PDOException $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    // Delete a status by statusID
    if (isset($inputData['action']) && $inputData['action'] === 'deleteStatus' && isset($inputData['statusID'])) {
        try {
            $statusID = $inputData['statusID'];
            $stmt = $pdo->prepare("DELETE FROM status WHERE statusID = ?");
            $stmt->execute([$statusID]);

            // Generate a random symmetric key
            $symmetricKey = openssl_random_pseudo_bytes(32);

            // Encrypt the data with the symmetric key (e.g., AES encryption)
            $encryptedData = openssl_encrypt(json_encode(["statusID" => $statusID]), 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, openssl_random_pseudo_bytes(16));

            // Encrypt the symmetric key with the public key
            openssl_public_encrypt($symmetricKey, $encryptedSymmetricKey, file_get_contents($publicKeyPath));

            // Combine the encrypted data and the encrypted symmetric key
            $encryptedPayload = $encryptedSymmetricKey . $encryptedData;

            echo json_encode(["message" => "Status deleted successfully", "encryptedData" => base64_encode($encryptedPayload)]);
        } catch (PDOException $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} else {
    echo json_encode(["error" => "Invalid request method"]);
}
?>
