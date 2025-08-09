<?php
$WAF_LEVEL = 8;

function waf_normalize($s) {
    // Normaliza URL e entidades HTML para detectar payloads camuflados
    $s = rawurldecode($s);
    $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $s = str_replace("\0", '', $s); // Remove null bytes
    $s = preg_replace('/\s+/', ' ', $s); // Normaliza espaços
    $s = strtolower($s); // Case insensitive para detecção
    return $s;
}

function waf_check_string_blacklist($s) {
    $patterns = [
        '/<\s*script\b/i',
        '/javascript:/i',
        '/on\w+\s*=/i',  
        '/<\s*iframe\b/i',
        '/<\s*img\b/i',
        '/<\s*svg\b/i',
        '/<\s*body\b/i',
        '/<\s*embed\b/i',
        '/<\s*object\b/i',
    ];

    foreach ($patterns as $pat) {
        if (preg_match($pat, $s)) return $pat;
    }
    return false;
}

function waf_check_array($arr, $prefix='') {
    foreach ($arr as $k => $v) {
        $key = $prefix === '' ? $k : $prefix . "[$k]";
        if (is_array($v)) {
            $res = waf_check_array($v, $key);
            if ($res) return $res;
        } else {
            $norm = waf_normalize((string)$v);
            $blk = waf_check_string_blacklist($norm);
            if ($blk) return "$key -> $blk";
        }
    }
    return false;
}

// Checar GET, POST e COOKIE para payloads suspeitos
$check = waf_check_array($_GET);
if (!$check) $check = waf_check_array($_POST);
if (!$check) $check = waf_check_array($_COOKIE);

if ($check) {
    http_response_code(403);
    echo "<h2>Request bloqueado pelo WAF (lab)</h2>";
    echo "<p>Motivo: padrão suspeito detectado em <code>$check</code></p>";
    exit;
}

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'");

$msgSucesso = '';
$msgErro = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';

    // Validação simples do email
    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        $msgErro = "<div class='msg-erro'>O e-mail informado não é válido.</div>";
    } else {
        // Intencionalmente vulnerável para laboratório de XSS
        $msgSucesso = "<div class='msg-sucesso'>Um link de recuperação foi enviado para: $email</div>";
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8" />
    <title>Recuperar Senha</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa, #d6eaf8);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: #fff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            width: 350px;
            animation: fadeIn 0.5s ease-in-out;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 20px;
        }
        label {
            font-weight: bold;
            color: #555;
            display: block;
            margin-top: 10px;
        }
        input {
            width: 100%;
            padding: 10px;
            margin-top: 4px;
            margin-bottom: 12px;
            border: 1px solid #ccc;
            border-radius: 6px;
            transition: border-color 0.3s;
        }
        input:focus {
            border-color: #27ae60;
            outline: none;
        }
        button {
            width: 100%;
            padding: 10px;
            background: #27ae60;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #1e8449;
        }
        a {
            display: block;
            text-align: center;
            margin-top: 15px;
            color: #3498db;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .msg-sucesso {
            color: #27ae60;
            background: #e8f8f5;
            padding: 10px;
            border-radius: 6px;
            margin-bottom: 15px;
            font-size: 14px;
            border: 1px solid #27ae60;
            text-align: center;
        }
        .msg-erro {
            color: #e74c3c;
            background: #fdecea;
            padding: 8px;
            border-radius: 6px;
            text-align: center;
            margin-bottom: 15px;
            font-size: 14px;
            border: 1px solid #e74c3c;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Recuperar minha senha</h1>
        <?php
        echo $msgErro;
        echo $msgSucesso;
        ?>
        <form method="POST" action="">
            <label for="email">Digite seu e-mail:</label>
            <input id="email" type="text" name="email" required autocomplete="off" />
            <button type="submit">Enviar</button>
        </form>
        <a href="login.php">Voltar ao login</a>
    </div>
</body>
</html>
