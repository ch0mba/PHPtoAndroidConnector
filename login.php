<?php
session_start();
include 'connection.php'; // Include the connection script

// Check if the request method exists and is POST
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] == 'POST') {
    // Retrieve posted data and sanitize input
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';

    // Input validation
    if (empty($username) || empty($password)) {
        echo json_encode(["status" => "error", "message" => "Username and password are required"]);
        $conn->close();
        exit;
    }

    // Prepared statement to prevent SQL injection
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    // Check if the user exists
    if ($result->num_rows > 0) {
        // Fetch the user record
        $user = $result->fetch_assoc();

        // Verify the password using password hashing (e.g., bcrypt)
        if (password_verify($password, $user['password'])) {
            //success message
            $response(["status" => "success", "message" => "Login successful"]);
        } else {
            $response(["status" => "error", "message" => "Invalid password"]);
        }
    } else {
        $response(["status" => "error", "message" => "User not found"]);
    }

        // Close the statement and connection
        $stmt->close();
    
    } else {
        $response(["status" => "error", "message" => "Invalid request method.Please use POST."]);
    }

// Return response as JSON
echo json_encode($response);
$conn->close();
?>
