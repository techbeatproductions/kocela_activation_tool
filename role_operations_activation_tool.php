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
    openssl_private_decrypt(base64_decode($data), $decrypted, $privateKey);
    return $decrypted;
}

// Public and private key file paths
$publicKeyPath = 'C:\MAMP\htdocs\kc_ios_public_key.pem';
$privateKeyPath = 'C:\MAMP\htdocs\kc_ios_private_key.pem';

// Check the HTTP request method
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Fetch all roles
    if (isset($_GET['action']) && $_GET['action'] === 'fetchAllRoles') {
        try {
            $stmt = $pdo->query("SELECT * FROM role");
            $roles = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Create an array that includes unencrypted and encrypted data
            $response = [
                "unencryptedData" => $roles,  // Include role IDs here
                "encryptedData" => rsaEncrypt(json_encode($roles), file_get_contents($publicKeyPath)),
            ];

            echo json_encode(["data" => $response]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }

    // Fetch a specific role by roleID
  elseif (isset($_GET['action']) && $_GET['action'] === 'fetchRole' && isset($_GET['roleID'])) {
      try {
          $roleID = $_GET['roleID'];
          $stmt = $pdo->prepare("SELECT * FROM role WHERE roleID = ?");
          $stmt->execute([$roleID]);
          $role = $stmt->fetch(PDO::FETCH_ASSOC);

          // Create an array that includes unencrypted and encrypted data
          $response = [
              "unencryptedData" => $role,  // Include role ID here
              "encryptedData" => rsaEncrypt(json_encode($role), file_get_contents($publicKeyPath)),
          ];

          echo json_encode(["data" => $response]);
      } catch (Exception $e) {
          echo json_encode(["error" => $e->getMessage()]);
      }
  }
}  elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Create a new role
    if (isset($inputData['action']) && $inputData['action'] === 'createRole' && isset($inputData['roleName'])) {
        try {
            $roleName = $inputData['roleName']; // You may want to add validation here

            $stmt = $pdo->prepare("INSERT INTO role (roleName) VALUES (?)");
            $stmt->execute([$roleName]);
            $newRoleID = $pdo->lastInsertId();

            // Return the new role ID after encryption
            $encryptedRoleID = rsaEncrypt(json_encode(["roleID" => $newRoleID]), file_get_contents($publicKeyPath));

            echo json_encode(["message" => "Role created successfully", "roleID" => $encryptedRoleID]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
    // Modify a role by roleID
    elseif (isset($inputData['action']) && $inputData['action'] === 'modifyRole' && isset($inputData['roleID']) && isset($inputData['newRoleName'])) {
        try {
            $roleID = $inputData['roleID'];
            $newRoleName = $inputData['newRoleName']; // You may want to add validation here

            $stmt = $pdo->prepare("UPDATE role SET roleName = ? WHERE roleID = ?");
            $stmt->execute([$newRoleName, $roleID]);

            // Return the modified role ID after encryption
            $encryptedRoleID = rsaEncrypt(json_encode(["roleID" => $roleID]), file_get_contents($publicKeyPath));

            echo json_encode(["message" => "Role modified successfully", "roleID" => $encryptedRoleID]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    // Delete a role by roleID
    if (isset($inputData['action']) && $inputData['action'] === 'deleteRole' && isset($inputData['roleID'])) {
        try {
            $roleID = $inputData['roleID'];
            $stmt = $pdo->prepare("DELETE FROM role WHERE roleID = ?");
            $stmt->execute([$roleID]);

            // Return the deleted role ID after encryption
            $encryptedRoleID = rsaEncrypt(json_encode(["roleID" => $roleID]), file_get_contents($publicKeyPath));

            echo json_encode(["message" => "Role deleted successfully", "roleID" => $encryptedRoleID]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} else {
    echo json_encode(["error" => "Invalid request method"]);
}
?>
