<?php
// waf.php embutido diretamente aqui para evitar problemas com require_once
// mas ideal é separar em waf.php e incluir no topo
// BEGIN WAF SIMPLES

// CONFIGURAÇÃO
$WAF_LEVEL = 8; // nível de proteção

// Funções auxiliares do WAF (normalização e blacklist)
function waf_normalize($s) {
    $s = rawurldecode($s);
    $s = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $s = str_replace("\0", '', $s);
    $s = preg_replace('/\s+/', ' ', $s);
    return $s;
}

function waf_check_string_blacklist($s) {
    $patterns = [
        '/<\s*script\b/i',
        '/javascript\s*:/i',
        '/on\w+\s*=/i',
        '/<\s*iframe\b/i',
        '/<\s*img\b[^>]*on/i',
        '/document\.cookie/i',
        '/eval\s*\(/i',
        '/<\s*svg\b/i',
        '/<\s*meta\b/i',
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

// Verificação simples
$check = waf_check_array($_GET);
if (!$check) $check = waf_check_array($_POST);
if (!$check) $check = waf_check_array($_COOKIE);

if ($check) {
    http_response_code(403);
    echo "<h2>Request bloqueado pelo WAF (lab)</h2>";
    exit;
}

// Envia header CSP ajustado para permitir estilos inline e css local
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'");

// END WAF
?>

<?php
$msgErro = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'] ?? '';
    $pass = $_POST['password'] ?? '';

    // Mensagem de erro para demonstração
    $msgErro = "<div class='msg-erro'>Usuário ou senha incorretos.</div>";
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8" />
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #e0f7fa, #f5f7fa);
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
            width: 320px;
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
            border-color: #3498db;
            outline: none;
        }
        button {
            width: 100%;
            padding: 10px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.3s;
        }
        button:hover {
            background: #2980b9;
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
        <h1>Login</h1>
        <?php echo $msgErro; ?>
        <form method="POST" action="">
            <label for="username">Usuário:</label>
            <input id="username" type="text" name="username" required />
            <label for="password">Senha:</label>
            <input id="password" type="password" name="password" required />
            <button type="submit">Entrar</button>
        </form>
        <a href="recuperar.php">Esqueci minha senha</a>
    </div>
</body>
</html>
