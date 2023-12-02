<?php
// Include your database connection file
include 'kocela_activation_tool_db_config.php';

// Get JSON data from the request
$jsonData = file_get_contents('php://input');
// Log the decoded JSON data
error_log("Decoded JSON data: " . print_r(json_decode($jsonData, true), true));



$data = json_decode($jsonData, true);

// Validate JSON data
if (!isset($data['action']) || !isset($data['email']) || !isset($data['newPassword'])) {
    echo json_encode(array('status' => 'failure', 'error' => 'Invalid action or parameters for POST request from play'));
    exit;
}

// Sanitize and validate user input
$action = $data['action'];
$email = $data['email']; // You should implement proper input validation here
$newPassword = $data['newPassword'];

// Perform action based on the provided action parameter
switch ($action) {
    case 'resetPassword':
        // Fetch user information from the user_credentials table
        $stmt = $pdo->prepare("SELECT userID FROM user WHERE email = ?");
        $stmt->execute(array($email));
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Update the password in the user_credentials table
            $stmt = $pdo->prepare("UPDATE user_credentials SET password = ? WHERE userID = ?");
            $stmt->execute(array($newPassword, $user['userID']));

            // Update the password in the user table (if you store passwords there)
            // $stmt = $pdo->prepare("UPDATE user SET password = ? WHERE email = ?");
            // $stmt->execute(array($newPassword, $email));

            echo json_encode(array('status' => 'success', 'message' => 'Password reset successfully'));
        } else {
            echo json_encode(array('status' => 'failure', 'error' => 'User not found'));
        }
        break;

    // Add more cases for additional actions if needed

    default:
        echo json_encode(array('status' => 'failure', 'error' => 'Invalid action'));
        break;
}
?>
