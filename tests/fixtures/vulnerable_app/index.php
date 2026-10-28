<?php
// Deliberately vulnerable demo code for SentinelGuard tests. Never deploy.
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
$res = mysqli_query($conn, $sql);
echo "Hello " . $_GET['name'];
include $_GET['page'] . ".php";
system("ping " . $_POST['host']);
$obj = unserialize($_COOKIE['data']);
eval($_REQUEST['code']);
$hash = md5($password);
ini_set('display_errors', 1);
$token = md5(rand());
