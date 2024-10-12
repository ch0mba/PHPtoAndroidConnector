<?php

include '../connection.php';


if ($_SERVER["REQUEST_METHOD"] == "POST")
{
    // Escape user inputs to prevent SQL injection
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Insert data into database
    $sql = "INSERT INTO users(username,password) VALUES (?, ?)";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param('ss', $username, $hashed_password);

    if ($stmt->execute()) {
    	//Succes message
    	$response['status'] ='success';
    	$response['message'] ='New record created successfully';
     
    } else {
    	//Erro message
    	$response['status'] ='error';
    	$response['message'] ='Error' . $stmt->error;

    }
    $stmt->close();

} else {
	//invalid request method
	$response['status'] = 'error';
	$response['message'] = 'Invalid request method';
}

// Return response as JSON
echo json_encode($response);
?>
