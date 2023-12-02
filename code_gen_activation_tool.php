<?php
// Retrieve input data from Postman
$inputJSON = file_get_contents('php://input');

// Log the original JSON data
error_log("Request (Code Generation API): Original JSON Data: " . json_encode($inputJSON, JSON_PRETTY_PRINT));

// Decode JSON data into an associative array
$inputData = json_decode($inputJSON, true);

// Check if decoding fails
if ($inputData === null && json_last_error() !== JSON_ERROR_NONE) {
    error_log("Failed to decode JSON data: " . json_last_error_msg());
    die("Failed to decode JSON data: " . json_last_error_msg());
}

// Log the original and complete requests
error_log("Request (Code Generation API): Original Request Data: " . json_encode($inputData, JSON_PRETTY_PRINT));
error_log("Request (Code Generation API): Complete Request: " . json_encode($inputData, JSON_PRETTY_PRINT));

// Load the public key for encryption
$publicKeyPath = 'C:\MAMP\htdocs\kc_ios_public_key.pem';
$publicKey = file_get_contents($publicKeyPath);

// Function to encrypt a specific field using RSA
function encryptField($field, $publicKey) {
    $encryptedField = '';
    openssl_public_encrypt($field, $encryptedField, $publicKey);
    return base64_encode($encryptedField);
}

// Function to format phone numbers
function formatPhoneNumber($phoneNumber) {
    $numericPhoneNumber = preg_replace('/[^0-9]/', '', $phoneNumber);

    if (substr($numericPhoneNumber, 0, 2) === '07') {
        return '2547' . substr($numericPhoneNumber, 2);
    } elseif (substr($numericPhoneNumber, 0, 2) === '01') {
        return '2541' . substr($numericPhoneNumber, 2);
    }

    return $numericPhoneNumber;
}


$inputData['req']['msisdn'] = formatPhoneNumber($inputData['req']['msisdn']);

// Encrypt specific fields within cred and req
$inputData['cred']['pass'] = encryptField($inputData['cred']['pass'], $publicKey);
$inputData['cred']['user'] = encryptField($inputData['cred']['user'], $publicKey);
$inputData['cred']['timestamp'] = encryptField($inputData['cred']['timestamp'], $publicKey);

$inputData['req']['ref'] = encryptField($inputData['req']['ref'], $publicKey);
$inputData['req']['pin'] = encryptField($inputData['req']['pin'], $publicKey);
$inputData['req']['msisdn'] = encryptField($inputData['req']['msisdn'], $publicKey);

// Log the data with encrypted fields
error_log("Request (Code Generation API): Data with Encrypted Fields: " . json_encode($inputData, JSON_PRETTY_PRINT));

// Echo the original and complete requests
echo "Original Request Data (CODE GEN API): " . json_encode($inputData, JSON_PRETTY_PRINT) . PHP_EOL;
echo "Request Data (CODE GEN API): " . json_encode($inputData, JSON_PRETTY_PRINT) . PHP_EOL;

// Send the request to the API
$options = [
    'http' => [
        'header'  => "Content-type: application/json\r\n",
        'method'  => 'POST',
        'content' => json_encode(['json_data' => $inputData]),
    ],
];

$context = stream_context_create($options);

$result = file_get_contents('https://jackal-modern-javelin.ngrok-free.app/otp_generation_activation_tool.php', false, $context);

// Log the result from the API
error_log("Request (Code Generation API): Result from (OTP GEN API): " . $result);

// Echo the result from the API
echo "Result from API (OTP GEN API): " . $result . PHP_EOL;

// Indicate that the data has been echoed and sent to the API
echo "Request echoed and sent to the API successfully!" . PHP_EOL;
?>
