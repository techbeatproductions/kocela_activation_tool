<?php
require 'kocela_activation_tool_db_config.php';

$inputJSON = file_get_contents('php://input');
$inputData = json_decode($inputJSON, true);

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

$publicKeyPath = 'C:\MAMP\htdocs\kc_ios_public_key.pem';
$privateKeyPath = 'C:\MAMP\htdocs\kc_ios_private_key.pem';

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Fetch all codes
    if (isset($inputData['action']) && $inputData['action'] === 'fetchAllCodes') {
        try {
            $stmt = $pdo->query("SELECT * FROM code");
            $codes = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Generate a random symmetric key
            $symmetricKey = openssl_random_pseudo_bytes(32); // 256 bits (change size as needed)

            // Encrypt your data with the symmetric key (e.g., using AES)
            $encryptedData = openssl_encrypt(json_encode($codes), 'aes-256-cbc', $symmetricKey, 0, $symmetricKey);

            // Encrypt the symmetric key with the RSA public key
            $encryptedSymmetricKey = rsaEncrypt($symmetricKey, file_get_contents($publicKeyPath));

            // Include the encrypted and decrypted data in the JSON response
            $decryptedData = json_encode($codes);

            echo json_encode([
                "data" => $encryptedData,
                "key" => $encryptedSymmetricKey,
                "decryptedData" => $decryptedData,
            ]);
        } catch (Exception $e) {
            error_log('Error in fetchAllCodes: ' . $e->getMessage());
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Create code
    if (isset($inputData['action']) && $inputData['action'] === 'createCode' && isset($inputData['code']) && isset($inputData['phoneNumberID']) && isset($inputData['generatedByUserID']) && isset($inputData['codeStatusID'])) {
        try {
            $code = $inputData['code'];
            $phoneNumberID = $inputData['phoneNumberID'];
            $generatedByUserID = $inputData['generatedByUserID'];
            $codeStatusID = $inputData['codeStatusID'];

            $stmt = $pdo->prepare("INSERT INTO code (code, phoneNumberID, generatedByUserID, codeStatusID) VALUES (?, ?, ?, ?)");
            $stmt->execute([$code, $phoneNumberID, $generatedByUserID, $codeStatusID]);
            $newCodeID = $pdo->lastInsertId();

            $encryptedCodeID = rsaEncrypt(json_encode(["codeID" => $newCodeID]), file_get_contents($publicKeyPath));

            echo json_encode([
                "message" => "Code created successfully",
                "codeID" => $encryptedCodeID,
                "data" => $code, // Include the unencrypted data
            ]);
        } catch (Exception $e) {
            error_log('Error in createCode: ' . $e->getMessage());
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    // Update code
    if (isset($inputData['action']) && $inputData['action'] === 'updateCode' && isset($inputData['codeID']) && isset($inputData['code']) && isset($inputData['phoneNumberID']) && isset($inputData['generatedByUserID']) && isset($inputData['codeStatusID'])) {
        try {
            $codeID = $inputData['codeID'];
            $code = $inputData['code'];
            $phoneNumberID = $inputData['phoneNumberID'];
            $generatedByUserID = $inputData['generatedByUserID'];
            $codeStatusID = $inputData['codeStatusID'];

            // Debugging: Add some logging to check variable values
            error_log("codeID: $codeID, code: $code, phoneNumberID: $phoneNumberID, generatedByUserID: $generatedByUserID, codeStatusID: $codeStatusID");

            $stmt = $pdo->prepare("UPDATE code SET code = ?, phoneNumberID = ?, generatedByUserID = ?, codeStatusID = ? WHERE codeID = ?");
            $stmt->execute([$code, $phoneNumberID, $generatedByUserID, $codeStatusID, $codeID]);

            // Check if the update was successful
            $updatedRows = $stmt->rowCount();

            if ($updatedRows > 0) {
                $encryptedCodeID = rsaEncrypt(json_encode(["codeID" => $codeID]), file_get_contents($publicKeyPath));
                echo json_encode([
                    "message" => "Code updated successfully",
                    "codeID" => $encryptedCodeID,
                    "data" => $code, // Include the unencrypted data
                ]);
            } else {
                echo json_encode(["error" => "Code update failed or no changes made."]);
            }
        } catch (PDOException $e) {
            error_log('Error in updateCode: ' . $e->getMessage());
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    // Delete code
    if (isset($inputData['action']) && $inputData['action'] === 'deleteCode' && isset($inputData['codeID'])) {
        try {
            $codeID = $inputData['codeID'];
            $stmt = $pdo->prepare("DELETE FROM code WHERE codeID = ?");
            $stmt->execute([$codeID]);

            $encryptedCodeID = rsaEncrypt(json_encode(["codeID" => $codeID]), file_get_contents($publicKeyPath));

            echo json_encode([
                "message" => "Code deleted successfully",
                "codeID" => $encryptedCodeID,
                "data" => $codeID, // Include the unencrypted data
            ]);
        } catch (Exception $e) {
            error_log('Error in deleteCode: ' . $e->getMessage());
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} else {
    echo json_encode(["error" => "Invalid request method"]);
}
?>
