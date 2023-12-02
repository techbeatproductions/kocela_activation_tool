<?php

// Include the database configuration file
require 'kocela_activation_tool_db_config.php';

// Retrieve $requestData from the POST request
$requestDataKey = 'json_data'; // Adjust this according to your actual key

$inputJSON = file_get_contents('php://input');
$inputData = json_decode($inputJSON, true);

if ($inputData && isset($inputData[$requestDataKey])) {
    $requestData = $inputData[$requestDataKey];

    // Load the private key for decryption
    $privateKeyPath = 'C:\MAMP\htdocs\kc_ios_private_key.pem';




    $privateKey = file_get_contents($privateKeyPath);




    // Check if the key is loaded successfully
    if ($privateKey === false) {
    die('Error loading private key');
    }

    // Function to decrypt a specific field using RSA
    function decryptField($field, $privateKey) {
    $decryptedField = '';
    $success = openssl_private_decrypt(
        base64_decode($field),
        $decryptedField,
        $privateKey,
        OPENSSL_PKCS1_PADDING,

    );

    if (!$success) {
        die('Error decrypting field');
    }

    return $decryptedField;
}



    // Decrypt specific fields
$decryptedPass = decryptField($requestData['cred']['pass'], $privateKey);
$decryptedUser = decryptField($requestData['cred']['user'], $privateKey);
$decryptedTimestamp = decryptField($requestData['cred']['timestamp'], $privateKey);

$decryptedRef = decryptField($requestData['req']['ref'], $privateKey);
$decryptedPin = decryptField($requestData['req']['pin'], $privateKey);
$decryptedMsisdn = decryptField($requestData['req']['msisdn'], $privateKey);


    // Continue with the rest of your existing code for processing the decrypted data

    // Echo the decrypted data
   echo "Decrypted Data:" . PHP_EOL;
   echo "Decrypted Password: " . $decryptedPass . PHP_EOL;
   echo "Decrypted User: " . $decryptedUser . PHP_EOL;
   echo "Decrypted Timestamp: " . $decryptedTimestamp . PHP_EOL;
   echo "Decrypted Ref: " . $decryptedRef . PHP_EOL;
   echo "Decrypted Pin: " . $decryptedPin . PHP_EOL;
   echo "Decrypted Msisdn: " . $decryptedMsisdn . PHP_EOL;

    // Search for the user with the given username
    $stmt = $pdo->prepare("SELECT * FROM user WHERE username = :username");
    $stmt->bindParam(':username', $decryptedUser);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // Store the user ID
        $userID = $user['userID'];

        // Fetch user credentials
        $stmt = $pdo->prepare("SELECT * FROM user_credentials WHERE userID = :userID");
        $stmt->bindParam(':userID', $userID);
        $stmt->execute();
        $credentials = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($credentials) {
            // Log the hashed password from the request and the stored hashed password


            error_log("Hashed Password from Request: " . $hashedPasswordInput);
            error_log("Stored Hashed Password: " . $credentials['password']);

            if ($decryptedPass === $credentials['password']) {
                // Check phone number and isAllowed
                $stmt = $pdo->prepare("SELECT * FROM phoneNumber WHERE phoneNumber = :phoneNumber");
                $stmt->bindParam(':phoneNumber', $decryptedMsisdn);
                $stmt->execute();
                $phoneNumber = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($phoneNumber && $phoneNumber['isAllowed']) {
                    // Save phoneNumberID to a global variable
                    $phoneNumberID = $phoneNumber['phoneNumberID'];

                    // Get the reference number from the request
                    $referenceNumber = $decryptedRef;

                    // Generate OTP
                    $otp = rand(10000, 99999);

                    // Insert into code table with referenceNumber
                    $stmt = $pdo->prepare("INSERT INTO code (code, phoneNumberID, generatedByUserID, codeStatusID, referenceNumber) VALUES (:code, :phoneNumberID, :userID, 3, :referenceNumber)");
                    $stmt->bindParam(':code', $otp);
                    $stmt->bindParam(':phoneNumberID', $phoneNumberID);
                    $stmt->bindParam(':userID', $userID);
                    $stmt->bindParam(':referenceNumber', $referenceNumber);
                    $stmt->execute();

                    // Get the last inserted codeID
                    $codeID = $pdo->lastInsertId();

                    // Check if the service exists
                    $stmt = $pdo->prepare("SELECT * FROM service WHERE serviceName = 'codegen'");
                    $stmt->execute();
                    $service = $stmt->fetch(PDO::FETCH_ASSOC);

                    if (!$service) {
                        // Insert into service table
                        $stmt = $pdo->prepare("INSERT INTO service (serviceName) VALUES ('codegen')");
                        $stmt->execute();

                        // Get the serviceID
                        $serviceID = $pdo->lastInsertId();
                    } else {
                        $serviceID = $service['serviceID'];
                    }

                    // Insert into auditTrail table
                    $stmt = $pdo->prepare("INSERT INTO auditTrail (serviceID, actorUserID, targetPhoneNumberID, targetCodeID) VALUES (:serviceID, :userID, :phoneNumberID, :codeID)");
                    $stmt->bindParam(':serviceID', $serviceID);
                    $stmt->bindParam(':userID', $userID);
                    $stmt->bindParam(':phoneNumberID', $phoneNumberID);
                    $stmt->bindParam(':codeID', $codeID);
                    $stmt->execute();

                    // Call the API after inserting into auditTrail
$apiUrl = 'https://jackal-modern-javelin.ngrok-free.app/auditTrail_operations_activation_tool.php/?action=fetchAllAuditTrail';
$response = file_get_contents($apiUrl);

// Check if the API call was successful
if ($response !== false) {
    // Process the API response if needed
    echo "API Response: " . $response;
} else {
    // Handle the case when the API call fails
    echo "Failed to call the API";
}


                    // Return success message and generated code
                    echo json_encode(['status' => "success", 'message' => 'Code generated successfully', 'code' => $otp]);
                } else {
                    echo json_encode(['status' => "failure", 'message' => 'Phone number not allowed']);
                }
            } else {
                echo json_encode(['status' => "failure", 'message' => 'Invalid credentials']);
            }
        } else {
            echo json_encode(['status' => "failure", 'message' => 'User credentials not found']);
        }
    } else {
        echo json_encode(['status' => "failure", 'message' => 'User not found']);
    }
} else {
    die("Request data not found");
}
?>
