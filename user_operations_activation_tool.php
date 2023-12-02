<?php
require "kocela_activation_tool_db_config.php";
// Parse the JSON data from the request body
$inputJSON = file_get_contents("php://input");
$inputData = json_decode($inputJSON, true);
// RSA encryption and decryption functions
function rsaEncrypt($data, $publicKey) {
    openssl_public_encrypt($data, $encryptedData, $publicKey);
    return base64_encode($encryptedData);
}
function rsaDecrypt($data, $privateKey) {
    openssl_private_decrypt(base64_decode($data), $decryptedData, $privateKey);
    return $decryptedData;
}
function formatPhoneNumber($phoneNumber) {
    $numericPhoneNumber = preg_replace('/[^0-9]/', '', $phoneNumber);

    // Check if the phone number starts with '07' or '01' and is 10 digits long
    if (strlen($numericPhoneNumber) == 10 && (substr($numericPhoneNumber, 0, 2) === '07' || substr($numericPhoneNumber, 0, 2) === '01')) {
        return '254' . substr($numericPhoneNumber, 1);
    }

    // Return the numeric phone number if no formatting is applied
    return $numericPhoneNumber;
}

// Public and private key file paths
$publicKeyPath = "kc_ios_public_key.pem";
$privateKeyPath = "kc_ios_private_key.pem";
try {
    if ($_SERVER["REQUEST_METHOD"] === "GET") {
        // Fetch all users
        if (isset($_GET["action"]) && $_GET["action"] === "fetchAllUsers") {
            $stmt = $pdo->query("SELECT
                                    u.*,
                                    r.roleName,
                                    s.statusName,
                                    c.username as createdByUsername
                                FROM user u
                                JOIN role r ON u.roleID = r.roleID
                                JOIN status s ON u.statusID = s.statusID
                                JOIN user c ON u.createdBy = c.userID");
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            // Encrypt the user data using RSA
            $encryptedUserData = rsaEncrypt(json_encode($users), file_get_contents($publicKeyPath));
            // Structure the response similar to fetching a specific user
            $formattedUsers = [];
            foreach ($users as $user) {
                $formattedUsers[] = ["user details" => ["username" => $user["username"], "firstName" => $user["firstName"], "lastName" => $user["lastName"], "phoneNumber" => $user["phoneNumber"], "createdAt" => $user["createdAt"], "modifiedAt" => $user["modifiedAt"], "role" => $user["roleName"], "status" => $user["statusName"], "created by" => $user["createdByUsername"],
                // Add other fields as needed
                ], ];
            }
            // Create a response that includes the encrypted data
            $response = ["status" => "success", "users" => $formattedUsers,
            // "encryptedData" => $encryptedUserData,
            ];
            echo json_encode(["data" => $response]);
        }
        // Fetch a specific user by username
        elseif (isset($_GET["action"]) && $_GET["action"] === "fetchUser" && isset($_GET["username"])) {
            $username = trim($_GET["username"]);
            $stmt = $pdo->prepare("
      SELECT
          u.username,
          u.firstName,
          u.lastName,
          u.phoneNumber,
          u.createdAt,
          u.modifiedAt,
          r.roleName,
          s.statusName,
          c.username as createdByUsername
      FROM user u
      JOIN role r ON u.roleID = r.roleID
      JOIN status s ON u.statusID = s.statusID
      JOIN user c ON u.createdBy = c.userID
      WHERE LOWER(u.username) = LOWER(?)
  ");
            error_log("SQL Query: " . $stmt->queryString);
            $stmt->execute([$username]);
            // Check for errors
            $errors = $stmt->errorInfo();
            if ($errors[0] !== "00000") {
                // Print the error information
                print_r($errors);
                exit(); // Stop execution to prevent further issues

            }
            // Fetch the user data
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                // Create a response that includes the data
                $response = ["status" => "success", "user" => ["user details" => ["username" => $user["username"], "firstName" => $user["firstName"], "lastName" => $user["lastName"], "phoneNumber" => $user["phoneNumber"], "createdAt" => $user["createdAt"], "modifiedAt" => $user["modifiedAt"], "role" => $user["roleName"], "status" => $user["statusName"], "created by" => $user["createdByUsername"], ], ], ];
                echo json_encode(["data" => $response]);
            } else {
                // Log the received username for debugging
                error_log("User not found for Username: $username");
                echo json_encode(["status" => "failure", "error" => "User not found for Username: $username", ]);
            }
        }
    } elseif ($_SERVER["REQUEST_METHOD"] === "POST") {
        // Create a new user
        if (isset($inputData["action"]) && $inputData["action"] === "createUser") {
            $username = $inputData["username"];
            $password = $inputData["password"];
            $roleID = 3;
            $statusID = 2;
            $createdBy = 3;
            $firstName = $inputData["firstName"];
            $lastName = $inputData["lastName"];
            $phoneNumber = $inputData["phoneNumber"];
            $email = $inputData["email"];

            $formattedPhoneNumber = formatPhoneNumber($phoneNumber);
            // Insert user data into the `user` table
            $stmt = $pdo->prepare("INSERT INTO user (username, roleID, statusID, createdBy, password, firstName, lastName, phoneNumber, email) VALUES (?, ?, ?, ?, ?, ?, ?, ?,?)");
            $stmt->execute([$username, $roleID, $statusID, $createdBy, $password, $firstName, $lastName, $formattedPhoneNumber,$email ]);
            $newUserID = $pdo->lastInsertId();
            // Handle image upload
            if (isset($_FILES["profileImage"]) && $_FILES["profileImage"]["error"] === UPLOAD_ERR_OK) {
                $uploadDir = "upload_directory/"; // Replace with your actual upload directory path
                $uploadedFileName = $_FILES["profileImage"]["name"];
                $uploadedFilePath = $uploadDir . $uploadedFileName;
                // Move the uploaded image to the desired location
                if (move_uploaded_file($_FILES["profileImage"]["tmp_name"], $uploadedFilePath)) {
                    // Insert image information into the `user_images` table
                    $stmt = $pdo->prepare("INSERT INTO user_images (userID, imageFileName, imageData) VALUES (?, ?, ?)");
                    $stmt->execute([$newUserID, $uploadedFileName, file_get_contents($uploadedFilePath), ]);
                }
            }
            // Insert user credentials into the `user_credentials` table with salt
            $stmt = $pdo->prepare("INSERT INTO user_credentials (userID, username, password, salt) VALUES (?, ?, ?, ?)");
            $stmt->execute([$newUserID, $username, $password, $salt]);
            // Return the new user ID, salt, and other information after encryption
            // Return only the encrypted new user ID
            $response = ["status" => "success", "message" => "Registration Successful await admin approval", "salutation" => "Welcome $username, you have successfully registered", ];
            echo json_encode(["data" => $response]);
        } elseif (isset($inputData["action"]) && $inputData["action"] === "modifyUser" && isset($inputData["username"])) {
            // Modify a user by username - Partial Update
            $username = $inputData["username"];
            $fieldsToUpdate = [];
            $fieldValues = [];
            // if (isset($inputData["password"])) {
            //     $fieldsToUpdate[] = "password = ?";
            //     $fieldValues[] = $inputData["password"];
            // }
            if (isset($inputData["firstName"])) {
                $fieldsToUpdate[] = "firstName = ?";
                $fieldValues[] = $inputData["firstName"];
            }
            if (isset($inputData["lastName"])) {
                $fieldsToUpdate[] = "lastName = ?";
                $fieldValues[] = $inputData["lastName"];
            }
            if (isset($inputData["phoneNumber"])) {
                $formattedPhoneNumber = formatPhoneNumber($inputData["phoneNumber"]);
                $fieldsToUpdate[] = "phoneNumber = ?";
                $fieldValues[] = $formattedPhoneNumber;
            }
            // Build the SQL query dynamically based on fields to update
            $query = "UPDATE user SET " . implode(", ", $fieldsToUpdate) . " WHERE username = ?";
            $fieldValues[] = $username;
            // Update the user's data in the database
            $stmt = $pdo->prepare($query);
            $stmt->execute($fieldValues);
            // Return the modified username
            $response = ["status" => "success", "message" => "$username modified successfully", ];
            echo json_encode(["data" => $response]);
        } elseif (isset($inputData["action"]) && $inputData["action"] === "userAuth" && isset($inputData["username"])) {
            $username = $inputData["username"];
            // Fetch hashed password and salt from user_credentials table
            $stmt = $pdo->prepare("SELECT password  FROM user_credentials WHERE username = ?");
            $stmt->execute([$username]);
            $credentials = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($credentials) {
                $hashedPassword = $credentials["password"];
                // Combine username and hashed password
                $combinedData = $username . $hashedPassword;
                // Hash the combined data using SHA256
                $hashedResult = hash("sha256", $combinedData);
                // Return the hashed result
                $response = ["status" => "success", "hashedResult" => $hashedResult, ];
                echo json_encode(["data" => $response]);
            } else {
                // Log the received username for debugging
                error_log("User not found for Username: $username");
                echo json_encode(["status" => "failure", "error" => "User not found for Username: $username", ]);
            }
        } elseif (isset($inputData["action"]) && $inputData["action"] === "makeAdmin" && isset($inputData["username"])) {
            // Make a user an admin
            $username = $inputData["username"];
            // Log action and username before fetching user ID
            error_log("Action: makeAdmin, Username: $username");
            // Fetch user ID based on the provided username
            $stmt = $pdo->prepare("SELECT userID, roleID FROM user WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                $userID = $user["userID"];
                // Check if the user is already an admin (roleID = 1)
                if ($user["roleID"] == 1) {
                    // User is already an admin
                    $response = ["status" => "failure", "error" => "$username is already an admin", ];
                    echo json_encode(["data" => $response]);
                } else {
                    // Update the user's roleID to 1 (admin)
                    $stmt = $pdo->prepare("UPDATE user SET roleID = 1 WHERE userID = ?");
                    $stmt->execute([$userID]);
                    // Return the modified user ID
                    $response = ["status" => "success", "message" => "$username is now an admin", ];
                    echo json_encode(["data" => $response]);
                }
            } else {
                // Log the received username for debugging
                error_log("User not found for Username: $username");
                echo json_encode(["status" => "failure", "error" => "$username not found", ]);
            }
        }
        // ...
        elseif (isset($inputData["action"]) && $inputData["action"] === "makeMultipleAdmins" && isset($inputData["usernames"]) && is_array($inputData["usernames"])) {
            // Make multiple users admins
            $usernames = $inputData["usernames"];
            // Log action and usernames before fetching user IDs
            error_log("Action: makeMultipleAdmins, Usernames: " . implode(", ", $usernames));
            // Fetch user details based on the provided usernames
            $placeholders = str_repeat("?, ", count($usernames) - 1) . "?";
            $stmt = $pdo->prepare("SELECT username, firstName, lastName, userID, roleID FROM user WHERE username IN ($placeholders)");
            $stmt->execute($usernames);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($users) {
                $alreadyAdminUsers = [];
                $userIDs = array_column($users, "userID");
                foreach ($users as $user) {
                    // Check if the user is already an admin (roleID is 1)
                    if ($user["roleID"] == 1) {
                        $alreadyAdminUsers[] = ["username" => $user["username"], "name" => $user["firstName"] . " " . $user["lastName"], ];
                    }
                }
                if (!empty($alreadyAdminUsers)) {
                    // Some users are already admins
                    $response = ["status" => "failure", "error" => "The following users are already admins:", "alreadyAdminUsers" => $alreadyAdminUsers, ];
                    echo json_encode(["data" => $response]);
                } else {
                    // Update the users' roleID to 1 (Admin)
                    $stmt = $pdo->prepare("UPDATE user SET roleID = 1 WHERE userID IN (" . implode(", ", $userIDs) . ")");
                    $stmt->execute();
                    // Return the modified user IDs
                    $response = ["status" => "success", "message" => "The following users have been made admins successfully", "adminUsers" => array_map(function ($user) {
                        return ["username" => $user["username"], "name" => $user["firstName"] . " " . $user["lastName"], ];
                    }, $users), ];
                    echo json_encode(["data" => $response]);
                }
            } else {
                // Log the received usernames for debugging
                error_log("Users not found for Usernames: " . implode(", ", $usernames));
                echo json_encode(["status" => "failure", "error" => "Users not found", ]);
            }
        }
        // ...
        elseif (isset($inputData["action"]) && $inputData["action"] === "activateUser" && isset($inputData["username"])) {
            // Activate a user
            $username = $inputData["username"];
            // Log action and username before fetching user ID
            error_log("Action: activateUser, Username: $username");
            // Fetch user ID, statusID, and roleID based on the provided username
            $stmt = $pdo->prepare("SELECT userID, statusID, roleID FROM user WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                $userID = $user["userID"];
                $statusID = $user["statusID"];
                // Check if the user is already activated (statusID = 1)
                if ($statusID == 1) {
                    // User is already activated
                    $response = ["status" => "failure", "error" => "$username is already activated", ];
                    echo json_encode(["data" => $response]);
                } else {
                    // Update the user's statusID to 1 (Active) and roleID to 2 (Regular)
                    $stmt = $pdo->prepare("UPDATE user SET statusID = 1, roleID = 2 WHERE userID = ?");
                    $stmt->execute([$userID]);
                    // Return the modified user ID
                    $response = ["status" => "success", "message" => "$username is now activated", ];
                    echo json_encode(["data" => $response]);
                }
            } else {
                // Log the received username for debugging
                error_log("User not found for Username: $username");
                echo json_encode(["status" => "failure", "error" => "User not found", ]);
            }
        } elseif (isset($inputData["action"]) && $inputData["action"] === "activateMultipleUsers" && isset($inputData["usernames"]) && is_array($inputData["usernames"])) {
            // Activate multiple users
            $usernames = $inputData["usernames"];
            // Log action and usernames before fetching user IDs
            error_log("Action: activateMultipleUsers, Usernames: " . implode(", ", $usernames));
            // Fetch user details based on the provided usernames
            $placeholders = str_repeat("?, ", count($usernames) - 1) . "?";
            $stmt = $pdo->prepare("SELECT username, firstName, lastName, userID, statusID FROM user WHERE username IN ($placeholders)");
            $stmt->execute($usernames);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($users) {
                $activatedUsers = [];
                foreach ($users as $user) {
                    // Check if the user is not already activated (statusID is not 1)
                    if ($user["statusID"] != 1) {
                        // Update the user's statusID to 1 (Active) and roleID to 2 (Regular)
                        $stmt = $pdo->prepare("UPDATE user SET statusID = 1, roleID = 2 WHERE userID = ?");
                        $stmt->execute([$user["userID"]]);
                        $activatedUsers[] = ["username" => $user["username"], "name" => $user["firstName"] . " " . $user["lastName"], ];
                    }
                }
                if (!empty($activatedUsers)) {
                    // Some users have been activated
                    $response = ["status" => "success", "message" => "The following users have been activated:", "activatedUsers" => $activatedUsers, ];
                    echo json_encode(["data" => $response]);
                } else {
                    // All users were already activated
                    $response = ["status" => "failure", "error" => "The following users are already activated", "alreadyActivatedUsers" => array_map(function ($user) {
                        return ["username" => $user["username"], "name" => $user["firstName"] . " " . $user["lastName"], ];
                    }, $users), ];
                    echo json_encode(["data" => $response]);
                }
            } else {
                // Log the received usernames for debugging
                error_log("Users not found for Usernames: " . implode(", ", $usernames));
                echo json_encode(["status" => "failure", "error" => "Users not found", ]);
            }
        } elseif (isset($inputData["action"]) && $inputData["action"] === "disableMultipleUsers" && isset($inputData["usernames"]) && is_array($inputData["usernames"])) {
            // Disable multiple users
            $usernames = $inputData["usernames"];
            // Log action and usernames before fetching user IDs
            error_log("Action: disableMultipleUsers, Usernames: " . implode(", ", $usernames));
            // Fetch user details based on the provided usernames
            $placeholders = str_repeat("?, ", count($usernames) - 1) . "?";
            $stmt = $pdo->prepare("SELECT username, firstName, lastName, userID, statusID FROM user WHERE username IN ($placeholders)");
            $stmt->execute($usernames);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($users) {
                $alreadyDisabledUsers = [];
                $userIDs = array_column($users, "userID");
                foreach ($users as $user) {
                    // Check if the user is already inactive (statusID is 2)
                    if ($user["statusID"] == 2) {
                        $alreadyDisabledUsers[] = ["username" => $user["username"], "name" => $user["firstName"] . " " . $user["lastName"], ];
                    }
                }
                if (!empty($alreadyDisabledUsers)) {
                    // Some users are already disabled
                    $response = ["status" => "failure", "error" => "The following users are already disabled:", "alreadyDisabledUsers" => $alreadyDisabledUsers, ];
                    echo json_encode(["data" => $response]);
                } else {
                    // Update the users' statusID to 2 (Inactive) and roleID to 3 (Unassigned)
                    $stmt = $pdo->prepare("UPDATE user SET statusID = 2, roleID = 3 WHERE userID IN (" . implode(", ", $userIDs) . ")");
                    $stmt->execute();
                    // Return the modified user IDs
                    $response = ["status" => "success", "message" => "The following users have been deactivated successfully", "deactivatedUsers" => array_map(function ($user) {
                        return ["username" => $user["username"], "name" => $user["firstName"] . " " . $user["lastName"], ];
                    }, $users), ];
                    echo json_encode(["data" => $response]);
                }
            } else {
                // Log the received usernames for debugging
                error_log("Users not found for Usernames: " . implode(", ", $usernames));
                echo json_encode(["status" => "failure", "error" => "Users not found", ]);
            }
        } elseif (isset($inputData["action"]) && $inputData["action"] === "disableUser" && isset($inputData["username"])) {
            // Disable a user
            $username = $inputData["username"];
            // Log action and username before fetching user ID
            error_log("Action: disableUser, Username: $username");
            // Fetch user ID and statusID based on the provided username
            $stmt = $pdo->prepare("SELECT userID, statusID FROM user WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            // Log the SQL query
            $sqlQuery = $stmt->queryString;
            error_log("SQL Query: $sqlQuery");
            if ($user) {
                $userID = $user["userID"];
                $statusID = $user["statusID"];
                // Check if the user is already Inactive (statusID is 2)
                if ($statusID == 2) {
                    // User is already disabled
                    $response = ["status" => "failure", "error" => "$username is already disabled", ];
                    echo json_encode(["data" => $response]);
                } else {
                    // Set the user's statusID to 3 (disabled)
                    $stmt = $pdo->prepare("UPDATE user SET statusID = 2 WHERE userID = ?");
                    $stmt->execute([$userID]);
                    // Return success message
                    $response = ["status" => "success", "message" => "$username disabled successfully", ];
                    echo json_encode(["data" => $response]);
                }
            } else {
                // Log the received username for debugging
                error_log("User not found for Username: $username");
                echo json_encode(["status" => "failure", "error" => "User not found", ]);
            }
        } else {
            // Log invalid action or parameters
            error_log("Invalid action or parameters for POST request");
            echo json_encode(["status" => "failure", "error" => "Invalid action or parameters for POST request", ]);
        }
    }
}
catch(Exception $e) {
    // Log the exception
    error_log("Exception: " . $e->getMessage());
    echo json_encode(["status" => "failure", "error" => $e->getMessage(), ]);
}
?>
