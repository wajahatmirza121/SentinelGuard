<?php
$id = (int) $_GET['id'];
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "Hello " . $name;
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$_POST['email']]);
include __DIR__ . '/header.php';
echo intval($_GET['n']);
system('ls ' . escapeshellarg($_GET['d']));
$h = password_hash($_POST['pw'], PASSWORD_DEFAULT);
// echo $_GET['commented_out'];
?>
<p><?= htmlspecialchars($_GET['q'] ?? '') ?></p>
