<?php
session_start();

// Uso de namespaces en lugar de require_once
use Inc\Config\Constants;
use Inc\Config\Db;

require_once '../../inc/config/constants.php';
require_once '../../inc/config/db.php';

// Inicialización de variables
$loginUsername = '';
$loginPassword = '';
$hashedPassword = '';

// Verificar si se recibió un POST con 'loginUsername'
if (isset($_POST['loginUsername'])) {
    $loginUsername = $_POST['loginUsername'];
    $loginPassword = $_POST['loginPassword'];

    // Validar que los campos no estén vacíos
    if (!empty($loginUsername) && !empty($loginPassword)) {
        // Sanitizar el username
        $loginUsername = filter_var($loginUsername, FILTER_SANITIZE_STRING);

        // Validar que username no esté vacío tras sanitización
        if ($loginUsername === '') {
            echo '<div class="alert alert-danger"><button type="button" class="close" data-dismiss="alert">&times;</button>Please enter Username</div>';
            exit();
        }

        // Validar que password no esté vacío
        if ($loginPassword === '') {
            echo '<div class="alert alert-danger"><button type="button" class="close" data-dismiss="alert">&times;</button>Please enter Password</div>';
            exit();
        }

        // Encriptar la contraseña
        $hashedPassword = md5($loginPassword);

        // Consultar las credenciales en la base de datos
        $checkUserSql = 'SELECT * FROM user WHERE username = :username AND password = :password';
        $checkUserStatement = $conn->prepare($checkUserSql);
        $checkUserStatement->execute([
            'username' => $loginUsername,
            'password' => $hashedPassword
        ]);

        // Verificar si existe el usuario
        if ($checkUserStatement->rowCount() > 0) {
            // Credenciales válidas: iniciar sesión
            $row = $checkUserStatement->fetch(PDO::FETCH_ASSOC);
            $_SESSION['loggedIn'] = '1';
            $_SESSION['fullName'] = $row['fullName'];

            echo '<div class="alert alert-success"><button type="button" class="close" data-dismiss="alert">&times;</button>Login success! Redirecting you to home page...</div>';
            exit();
        } else {
            echo '<div class="alert alert-danger"><button type="button" class="close" data-dismiss="alert">&times;</button>Incorrect Username / Password</div>';
            exit();
        }
    } else {
        echo '<div class="alert alert-danger"><button type="button" class="close" data-dismiss="alert">&times;</button>Please enter Username and Password</div>';
        exit();
    }
}
