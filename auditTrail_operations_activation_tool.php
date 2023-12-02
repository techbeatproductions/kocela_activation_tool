<?php
require 'kocela_activation_tool_db_config.php';

$inputJSON = file_get_contents('php://input');
$inputData = json_decode($inputJSON, true);

function fetchUserUsername($userID, $pdo) {
    $stmt = $pdo->prepare("SELECT username FROM user WHERE userID = ?");
    $stmt->execute([$userID]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Check if $user is not false before trying to access the array offset
    return ($user !== false) ? $user['username'] : null;
}

function fetchPhoneNumber($phoneNumberID, $pdo) {
    $stmt = $pdo->prepare("SELECT phoneNumber FROM phoneNumber WHERE phoneNumberID = ?");
    $stmt->execute([$phoneNumberID]);
    $phoneNumber = $stmt->fetch(PDO::FETCH_ASSOC);
    return $phoneNumber['phoneNumber'];
}

function fetchCode($codeID, $pdo) {
    $stmt = $pdo->prepare("SELECT code, referenceNumber FROM code WHERE codeID = ?");
    $stmt->execute([$codeID]);
    $code = $stmt->fetch(PDO::FETCH_ASSOC);
    return $code;
}

function fetchServiceName($serviceID, $pdo) {
    $stmt = $pdo->prepare("SELECT serviceName FROM service WHERE serviceID = ?");
    $stmt->execute([$serviceID]);
    $service = $stmt->fetch(PDO::FETCH_ASSOC);
    return $service['serviceName'];
}

function fetchAuditTrailByUsername($username, $pdo) {
    $stmt = $pdo->prepare("SELECT * FROM auditTrail WHERE actorUserID IN (SELECT userID FROM user WHERE username = ?) OR targetUserID IN (SELECT userID FROM user WHERE username = ?)");
    $stmt->execute([$username, $username]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Fetch all audit trail entries
    if (isset($_GET['action']) && $_GET['action'] === 'fetchAllAuditTrail') {
        try {
            $stmt = $pdo->query("SELECT * FROM auditTrail");
            $auditTrail = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $response = formatAuditTrailData($auditTrail, $pdo);

            echo json_encode([
                "data" => $response,
            ]);
        } catch (Exception $e) {
            echo json_encode(["error" => $e->getMessage()]);
        }
    } elseif (isset($_GET['action']) && $_GET['action'] === 'fetchAuditTrail' && isset($_GET['username'])) {
        // Fetch audit trail entries for a specific username
        try {
            $username = $_GET['username'];



            // Log the action and username
            error_log("Action: fetchAuditTrail");
            error_log("Username: $username");

            // Fetch audit trail entries by username
            $auditTrailByUsername = fetchAuditTrailByUsername($username, $pdo);

            if (!empty($auditTrailByUsername)) {
                // Format and respond with the audit trail data
                $response = formatAuditTrailData($auditTrailByUsername, $pdo);
                echo json_encode(["data" => $response]);
            } else {
                // Respond with an error message if no entries are found
                echo json_encode(["error" => "No audit trail entries found for the specified username"]);
            }
        } catch (Exception $e) {
            // Respond with an error message if an exception occurs
            echo json_encode(["error" => $e->getMessage()]);
        }
    }
    // ... (other conditions)
} else {
    echo json_encode(["error" => "Invalid request method"]);
}

function formatAuditTrailData($auditTrail, $pdo) {
    $formattedData = [];

    // Check if $auditTrail is an array
    if (is_array($auditTrail)) {
        foreach ($auditTrail as $entry) {
            // Check if $entry is an array
            if (is_array($entry)) {
                $actorUsername = fetchUserUsername($entry['actorUserID'], $pdo);
                $targetUsername = fetchUserUsername($entry['targetUserID'], $pdo);
                $targetPhoneNumber = fetchPhoneNumber($entry['targetPhoneNumberID'], $pdo);
                $targetCode = fetchCode($entry['targetCodeID'], $pdo);
                $serviceName = fetchServiceName($entry['serviceID'], $pdo);

                $entry['actorUsername'] = $actorUsername;

                if ($targetUsername !== null) {
                    $entry['targetUsername'] = $targetUsername;
                }

                $entry['targetPhoneNumber'] = $targetPhoneNumber;

              
                $entry['targetCode'] = $targetCode;
                $entry['serviceName'] = $serviceName;

                unset($entry['actorUserID'], $entry['targetUserID'], $entry['targetPhoneNumberID'], $entry['targetCodeID'], $entry['serviceID']);

                $formattedData[] = $entry;
            } else {
                // Log or handle the case where $entry is not an array
                error_log("Invalid entry format: " . print_r($entry, true));
            }
        }
    } else {
        // Log or handle the case where $auditTrail is not an array
        error_log("Invalid auditTrail format: " . print_r($auditTrail, true));
    }

    return $formattedData;
}
?>
