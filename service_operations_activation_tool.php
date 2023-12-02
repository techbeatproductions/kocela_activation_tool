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
    // Fetch all services
    if (isset($_GET['action']) && $_GET['action'] === 'fetchAllServices') {
        try {
            $stmt = $pdo->query("SELECT * FROM service");
            $services = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Create an array that includes unencrypted and encrypted data
            $response = [
                "unencryptedData" => $services,  // Include service IDs here
                "encryptedData" => rsaEncrypt(json_encode($services), file_get_contents($publicKeyPath)),
            ];

            echo json_encode(["data" => $response]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }

    // Fetch a specific service by serviceID
      elseif (isset($_GET['action']) && $_GET['action'] === 'fetchService' && isset($_GET['serviceID'])) {
          $serviceID = $_GET['serviceID'];
          try {
              $stmt = $pdo->prepare("SELECT * FROM service WHERE serviceID = ?");
              $stmt->execute([$serviceID]);
              $service = $stmt->fetch(PDO::FETCH_ASSOC);

              // Create an array that includes unencrypted and encrypted data
              $response = [
                  "unencryptedData" => $service,  // Include service ID here
                  "encryptedData" => rsaEncrypt(json_encode($service), file_get_contents($publicKeyPath)),
              ];

              echo json_encode(["data" => $response]);
          } catch (Exception $e) {
              echo json_encode(["error" => $e->getMessage()]);
          }
      }
  } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Create a new service
    if (isset($inputData['action']) && $inputData['action'] === 'createService' && isset($inputData['serviceName'])) {
        try {
            $serviceName = $inputData['serviceName']; // You may want to add validation here

            $stmt = $pdo->prepare("INSERT INTO service (serviceName) VALUES (?)");
            $stmt->execute([$serviceName]);
            $newServiceID = $pdo->lastInsertId();

            // Return the new service ID after encryption
            $encryptedServiceID = rsaEncrypt(json_encode(["serviceID" => $newServiceID]), file_get_contents($publicKeyPath));

            echo json_encode(["message" => "Service created successfully", "serviceID" => $encryptedServiceID]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
    // Modify a service by serviceID
    elseif (isset($inputData['action']) && $inputData['action'] === 'modifyService' && isset($inputData['serviceID']) && isset($inputData['newServiceName'])) {
        try {
            $serviceID = $inputData['serviceID'];
            $newServiceName = $inputData['newServiceName']; // You may want to add validation here

            $stmt = $pdo->prepare("UPDATE service SET serviceName = ? WHERE serviceID = ?");
            $stmt->execute([$newServiceName, $serviceID]);

            // Return the modified service ID after encryption
            $encryptedServiceID = rsaEncrypt(json_encode(["serviceID" => $serviceID]), file_get_contents($publicKeyPath));

            echo json_encode(["message" => "Service modified successfully", "serviceID" => $encryptedServiceID]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    // Delete a service by serviceID
    if (isset($inputData['action']) && $inputData['action'] === 'deleteService' && isset($inputData['serviceID'])) {
        try {
            $serviceID = $inputData['serviceID'];
            $stmt = $pdo->prepare("DELETE FROM service WHERE serviceID = ?");
            $stmt->execute([$serviceID]);

            // Return the deleted service ID after encryption
            $encryptedServiceID = rsaEncrypt(json_encode(["serviceID" => $serviceID]), file_get_contents($publicKeyPath));

            echo json_encode(["message" => "Service deleted successfully", "serviceID" => $encryptedServiceID]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
} else {
    echo json_encode(["error" => "Invalid request method"]);
}
?>
