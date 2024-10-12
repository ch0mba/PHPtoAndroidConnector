<?php

$servername = "localhost:3306"; // Replace with your server name
$username = "root"; // Replace with your username
$password = ""; // Replace with your password
$database = "android"; // Replace with your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

?>