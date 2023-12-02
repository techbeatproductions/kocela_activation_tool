<?php
require 'kocela_activation_tool_db_config.php';

// Parse the JSON data from the request body
$inputJSON = file_get_contents('php://input');
$inputData = json_decode($inputJSON, true);

// RSA encryption and decryption functions
function rsaEncrypt($data, $publicKey)
{
    openssl_public_encrypt($data, $encrypted, $publicKey);
    return base64_encode($encrypted);
}

function rsaDecrypt($data, $privateKey)
{
    $decrypted = null;
    if (openssl_private_decrypt(base64_decode($data), $decrypted, $privateKey)) {
        return $decrypted;
    } else {
        error_log('Decryption error: ' . openssl_error_string());
        return null;
    }
}

// Public and private key file paths
$publicKeyPath = 'C:\MAMP\htdocs\kc_ios_public_key.pem';
$privateKeyPath = 'C:\MAMP\htdocs\kc_ios_private_key.pem';

// Check the HTTP request method
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Fetch all phone numbers
    if (isset($inputData['action']) && $inputData['action'] === 'fetchAllPhoneNumbers') {
        try {
            $stmt = $pdo->query("SELECT * FROM phoneNumber");
            $phoneNumbers = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Debugging: Log the phone numbers data
            error_log('Fetched phoneNumbers:');
            error_log(print_r($phoneNumbers, true));

            // Encrypt the phone numbers data before sending
            $encryptedPhoneNumbers = rsaEncrypt(json_encode($phoneNumbers), file_get_contents($publicKeyPath));

            // Decrypt the data for debugging purposes
            $decryptedPhoneNumbers = rsaDecrypt($encryptedPhoneNumbers, file_get_contents($privateKeyPath));

            error_log('Decrypted Data:');
            error_log(print_r($decryptedPhoneNumbers, true));

            echo json_encode(["data" => $encryptedPhoneNumbers, "decryptedData" => $decryptedPhoneNumbers]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }

    // Fetch a specific phone number by phoneNumberID
    elseif (isset($inputData['action']) && $inputData['action'] === 'fetchPhoneNumber' && isset($inputData['phoneNumberID'])) {
        try {
            $phoneNumberID = $inputData['phoneNumberID'];
            $stmt = $pdo->prepare("SELECT * FROM phoneNumber WHERE phoneNumberID = ?");
            $stmt->execute([$phoneNumberID]);
            $phoneNumber = $stmt->fetch(PDO::FETCH_ASSOC);

            // Debugging: Log the phone number entry data
            error_log('Fetched phoneNumber:');
            error_log(print_r($phoneNumber, true));

            // Encrypt the phone number entry data before sending
            $encryptedPhoneNumber = rsaEncrypt(json_encode($phoneNumber), file_get_contents($publicKeyPath));

            // Decrypt the data for debugging purposes
            $decryptedPhoneNumber = rsaDecrypt($encryptedPhoneNumber, file_get_contents($privateKeyPath));

            echo json_encode(["data" => $encryptedPhoneNumber, "decryptedData" => $decryptedPhoneNumber]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }

    // Check if a phone number exists in the database
    elseif (isset($inputData['action']) && $inputData['action'] === 'checkPhoneNumberExists' && isset($inputData['phoneNumber'])) {
        try {
            $phoneNumber = $inputData['phoneNumber'];

            $stmt = $pdo->prepare("SELECT COUNT(*) FROM phoneNumber WHERE phoneNumber = ?");
            $stmt->execute([$phoneNumber]);
            $count = $stmt->fetchColumn();

            if ($count > 0) {
                echo json_encode(["message" => "Phone number exists", "phoneNumber" => $phoneNumber]);
            } else {
                echo json_encode(["message" => "Phone number does not exist", "phoneNumber" => $phoneNumber]);
            }
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Create a new phone number
    if (isset($inputData['action']) && $inputData['action'] === 'createPhoneNumber' && isset($inputData['phoneNumber']) && isset($inputData['isAllowed']) && isset($inputData['createdBy'])) {
        try {
            $phoneNumber = $inputData['phoneNumber']; // You may want to add validation here
            $isAllowed = $inputData['isAllowed'];
            $createdBy = $inputData['createdBy']; // You may want to validate this

            $stmt = $pdo->prepare("INSERT INTO phoneNumber (phoneNumber, isAllowed, createdBy) VALUES (?, ?, ?)");
            $stmt->execute([$phoneNumber, $isAllowed, $createdBy]);
            $newPhoneNumberID = $pdo->lastInsertId();

            // Debugging: Log information about the new phone number
            error_log('Created new phoneNumber with ID: ' . $newPhoneNumberID);

            echo json_encode(["message" => "Phone number created successfully", "phoneNumberID" => $newPhoneNumberID]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    // Update a phone number by phoneNumberID
    if (isset($inputData['action']) && $inputData['action'] === 'updatePhoneNumber' && isset($inputData['phoneNumberID']) && isset($inputData['phoneNumber']) && isset($inputData['isAllowed']) && isset($inputData['modifiedBy'])) {
        try {
            $phoneNumberID = $inputData['phoneNumberID'];
            $phoneNumber = $inputData['phoneNumber']; // You may want to add validation here
            $isAllowed = $inputData['isAllowed'];
            $modifiedBy = $inputData['modifiedBy']; // You may want to validate this

            // Debugging: Log information about the phone number update
            error_log('Updating phoneNumber with ID: ' . $phoneNumberID);
            error_log('Updated phoneNumber: ' . $phoneNumber);
            error_log('isAllowed: ' . $isAllowed);
            error_log('modifiedBy: ' . $modifiedBy);

            $stmt = $pdo->prepare("UPDATE phoneNumber SET phoneNumber = ?, isAllowed = ?, modifiedBy = ? WHERE phoneNumberID = ?");
            $stmt->execute([$phoneNumber, $isAllowed, $modifiedBy, $phoneNumberID]);

            echo json_encode(["message" => "Phone number updated successfully", "phoneNumberID" => $phoneNumberID]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    // Delete a phone number by phoneNumberID
    if (isset($inputData['action']) && $inputData['action'] === 'deletePhoneNumber' && isset($inputData['phoneNumberID'])) {
        try {
            $phoneNumberID = $inputData['phoneNumberID'];
            $stmt = $pdo->prepare("DELETE FROM phoneNumber WHERE phoneNumberID = ?");
            $stmt->execute([$phoneNumberID]);

            // Debugging: Log information about the deleted phone number
            error_log('Deleted phoneNumber with ID: ' . $phoneNumberID);

            echo json_encode(["message" => "Phone number deleted successfully", "phoneNumberID" => $phoneNumberID]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} else {
    echo json_encode(["error" => "Invalid request method"]);
}
?>
