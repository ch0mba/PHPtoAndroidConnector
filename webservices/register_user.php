<?php

include '../connection.php';


if ($_SERVER["REQUEST_METHOD"] == "POST")
{
    // Escape user inputs to prevent SQL injection
    $username = $_POST['username'];
    $first_name= $_POST['first_name'];
    $last_name = $_POST['last_name'];
    $password = $_POST['password'];


    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Insert data into database
    $sql = "INSERT INTO users(username,first_name,last_name,password) VALUES (?, ?, ?, ?)";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param('ssss', $username,$first_name,$last_name, $hashed_password);

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
