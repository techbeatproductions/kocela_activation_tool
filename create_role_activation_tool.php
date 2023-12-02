<?php
require 'kocela_activation_tool_db_config.php';

// Check if the request is a POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $requestData = json_decode(file_get_contents('php://input'), true);

        // Assuming that the JSON contains 'roleName' field
        $roleName = $requestData['roleName'];

        // Perform RSA decryption here if necessary

        // Insert data into the 'role' table without specifying roleID (auto-incremented)
        $stmt = $pdo->prepare("INSERT INTO role (roleName) VALUES (?)");
        $stmt->execute([$roleName]);

        // Retrieve the last inserted roleID
        $newRoleID = $pdo->lastInsertId();

        echo json_encode(["message" => "Role created successfully", "roleID" => $newRoleID]);
    } catch (Exception $e) {
        echo json_encode(["error" => $e->getMessage()]);
    }
} else {
    echo json_encode(["error" => "Invalid request method"]);
}
?>
