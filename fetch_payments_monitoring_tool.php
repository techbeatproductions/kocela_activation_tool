<?php

require 'kocela_activation_tool_db_config.php';

function fetchAllPayments($pdo) {
    $stmt = $pdo->query("SELECT * FROM payments_platform");
    $allData = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $totalTransactions = count($allData);

    return [
        "data" => $allData,
        "totalTransactions" => $totalTransactions
    ];
}

function failedMetrics($allData) {
    $failedTransactionCount = 0;
    $failedTransactions = [];
    foreach ($allData['data'] as $transaction) {
        if ($transaction['paymentStatus'] == 4) {
            $failedTransactionCount++;
            $failedTransactions[] = $transaction;
        }
    }

    return [
        "failedTransactionCount" => $failedTransactionCount,
        "failedTransactions" => $failedTransactions
    ];
}

function succeededMetrics($allData) {
    $successfulTransactionCount = 0;
    $successfulTransactions = [];
    foreach ($allData['data'] as $transaction) {
        if ($transaction['paymentStatus'] != 4) {
            $successfulTransactionCount++;
            $successfulTransactions[] = $transaction;
        }
    }

    return [
        "successfulTransactionCount" => $successfulTransactionCount,
        "successfulTransactions" => $successfulTransactions
    ];
}

try {
    if (isset($_GET['action'])) {
        $action = $_GET['action'];

        if ($action === 'fetchAllPayments') {
            $result = fetchAllPayments($pdo);
            echo json_encode($result);
        } elseif ($action === 'failedMetrics' || $action === 'succeededMetrics') {
            $allData = fetchAllPayments($pdo);
            $metrics = ($action === 'failedMetrics') ? failedMetrics($allData) : succeededMetrics($allData);

            echo json_encode([
                "metrics" => $metrics,
                "totalTransactions" => $allData['totalTransactions']
            ]);
        } else {
            echo json_encode(["error" => "Unknown action"]);
        }
    } else {
        echo json_encode(["error" => "Missing action parameter"]);
    }
} catch (Exception $e) {
    echo json_encode(["error" => $e->getMessage()]);
}
?>
