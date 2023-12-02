<?php

require 'kocela_activation_tool_db_config.php';

function fetchSessionUSSDApplicationData($pdo) {
    $stmt = $pdo->query("SELECT * FROM session_ussd_application");
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

try {
    // Check if 'action' is present in the query parameters
    if (isset($_GET['action'])) {
        $action = $_GET['action'];

        if ($action === 'fetchSessionMonitoring') {
            // Fetch data from the session_ussd_application table
            $sessionUSSDApplicationData = fetchSessionUSSDApplicationData($pdo);

            echo json_encode([
                "data" => $sessionUSSDApplicationData,
            ]);
        } else {
            // Respond with an error message for an unknown action
            echo json_encode(["error" => "Unknown action"]);
        }
    } else {
        // Respond with an error message for missing action parameter
        echo json_encode(["error" => "Missing action parameter"]);
    }
} catch (Exception $e) {
    // Respond with an error message for any exception
    echo json_encode(["error" => $e->getMessage()]);
}
?>
