<?php

/////////////////////////////////////////////////
  /*!
   * WebTaskmgr / ATK-FM v2.0.1
   * 単一のPHPファイルだけで完結する多機能タスクマネージャーです。
   * これ一つでプロセス管理からファイル編集までできます！
   *
   * Copyright 2025 ActiveTK. All rights reserved.
   * Released under the MIT License
  */
/////////////////////////////////////////////////

// === APP_CONFIG_START ===
$APP_CONFIG = [
  "PASSWORD_HASH" => null,
  "IP_ALLOW" => [],
  "RUN_AS_ROOT" => false,
];
// === APP_CONFIG_END ===

if (!empty($APP_CONFIG["IP_ALLOW"])) {
  $cli = $_SERVER["REMOTE_ADDR"] ?? "";
  if (!is_ip_allowed($cli, $APP_CONFIG["IP_ALLOW"])) {
    header("HTTP/1.1 403 Forbidden");
    header("Content-Type: text/plain; charset=utf-8");
    echo "403 Forbidden (Your IP: {$cli})";
    exit();
  }
}

function is_authed(): bool
{
  if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
  }
  return !empty($_SESSION["atkfm_authed"]);
}

function render_login_and_exit(string $error = ""): void
{
  header("Content-Type: text/html; charset=utf-8");
  $action = htmlspecialchars(
    self_path() . "?action=login",
    ENT_QUOTES | ENT_SUBSTITUTE,
    "UTF-8"
  );
  ?>
    <!doctype html>
    <html lang="ja">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>ログイン - WebTaskmgr / ATK-FM</title>
      <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="min-h-screen bg-slate-900 text-slate-100 flex items-center justify-center">
      <form method="post" action="<?= $action ?>"
            class="w-full max-w-sm p-6 rounded-lg border border-slate-800 bg-slate-800/40 space-y-4">
        <div class="text-lg font-semibold">ログイン</div>
        <?php if ($error !== ""): ?>
          <div class="text-sm text-rose-300"><?= htmlspecialchars(
            $error,
            ENT_QUOTES | ENT_SUBSTITUTE,
            "UTF-8"
          ) ?></div>
        <?php endif; ?>
        <label class="block text-sm">
          <span class="text-slate-300">パスワード</span>
          <input type="password" name="password"
                 class="mt-1 w-full rounded border border-slate-700 bg-slate-900/70 px-3 py-2"
                 autocomplete="current-password" required>
        </label>
        <button type="submit"
                class="w-full px-4 py-2 rounded bg-blue-600 hover:bg-blue-500">ログイン</button>
      </form>
    </body>
    </html>
    <?php exit();
}

function auth_gate(array $APP_CONFIG): void
{
  if (empty($APP_CONFIG["PASSWORD_HASH"])) {
    return;
  }

  if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
  }

  if (isset($_GET["action"]) && $_GET["action"] === "login") {
    if (($_SERVER["REQUEST_METHOD"] ?? "GET") === "POST") {
      $pw = (string) ($_POST["password"] ?? "");
      if (password_verify($pw, $APP_CONFIG["PASSWORD_HASH"])) {
        $_SESSION["atkfm_authed"] = 1;
        header("Location: " . self_path(), true, 303);
        exit();
      }
      render_login_and_exit("パスワードが違います。");
    }
    render_login_and_exit();
  }

  if (!is_authed()) {
    render_login_and_exit();
  }
}

function client_ip(): string
{
  return $_SERVER["REMOTE_ADDR"] ?? "";
}

function self_path(): string
{
  $p = parse_url($_SERVER["REQUEST_URI"] ?? "/", PHP_URL_PATH);
  return $p ?: "/";
}

function is_ip_allowed(string $ip, array $allow): bool
{
  if ($ip === "") {
    return false;
  }
  foreach ($allow as $pat) {
    $pat = trim((string) $pat);
    if ($pat === "") {
      continue;
    }
    if (strpos($pat, "/") !== false) {
      // CIDR
      if (ip_in_cidr($ip, $pat)) {
        return true;
      }
    } else {
      // exact
      if (strcasecmp($ip, $pat) === 0) {
        return true;
      }
    }
  }
  return false;
}
function ip_in_cidr(string $ip, string $cidr): bool
{
  [$subnet, $bits] = explode("/", $cidr, 2) + [null, null];
  $ip_bin = @inet_pton($ip);
  $sub_bin = @inet_pton($subnet);
  if ($ip_bin === false || $sub_bin === false) {
    return false;
  }
  $bits = (int) $bits;
  $len = strlen($ip_bin);
  if ($len !== strlen($sub_bin)) {
    return false;
  } // v4/v6 混在回避
  $bytes = intdiv($bits, 8);
  $rem = $bits % 8;
  if (
    $bytes > 0 &&
    substr($ip_bin, 0, $bytes) !== substr($sub_bin, 0, $bytes)
  ) {
    return false;
  }
  if ($rem === 0) {
    return true;
  }
  $mask = chr((0xff << 8 - $rem) & 0xff);
  return (ord($ip_bin[$bytes]) & ord($mask)) ===
    (ord($sub_bin[$bytes]) & ord($mask));
}

function cfg_write(array $new): array
{
  $self = __FILE__;
  $code = @file_get_contents($self);
  if ($code === false) {
    $code = app_run_as_root_enabled() ? root_fs_read($self) : false;
    if ($code === false) {
      return ["ok" => false, "error" => "read self failed"];
    }
  }

  $startTag = "// === APP_CONFIG_START ===";
  $endTag   = "// === APP_CONFIG_END ===";
  $start = strpos($code, $startTag);
  $end   = strpos($code, $endTag);
  if ($start === false || $end === false || $end <= $start) {
    return ["ok" => false, "error" => "config block not found"];
  }

  $pwd     = $new["PASSWORD_HASH"] ?? null;
  $ipA     = array_values(array_filter(array_map("trim", (array)($new["IP_ALLOW"] ?? [])), fn($x) => $x !== ""));
  $runRoot = !empty($new["RUN_AS_ROOT"]);

  $pwdCode = $pwd === null ? "null" : var_export($pwd, true);
  $ipCode  = var_export($ipA, true);
  $runCode = $runRoot ? 'true' : 'false';

  $block =
    $startTag . "\n" .
    "\$APP_CONFIG = [\n" .
    "  'PASSWORD_HASH' => {$pwdCode},\n" .
    "  'IP_ALLOW'      => {$ipCode},\n" .
    "  'RUN_AS_ROOT'   => {$runCode},\n" .
    "];\n" .
    $endTag;

  $before  = substr($code, 0, $start);
  $after   = substr($code, $end + strlen($endTag));
  $newCode = $before . $block . $after;

  $ok = @file_put_contents($self, $newCode, LOCK_EX);
  if ($ok !== false) return ["ok" => true];

  if (app_run_as_root_enabled()) {
    $tmp = @tempnam(sys_get_temp_dir(), 'atkfm_cfg_');
    if ($tmp === false || @file_put_contents($tmp, $newCode) === false) {
      return ["ok" => false, "error" => "write temp failed"];
    }
    $out = []; $rc = 0;
    exec_sudo('install -m 0644 ' . escapeshellarg($tmp) . ' ' . escapeshellarg($self) . ' 2>&1', $out, $rc);
    @unlink($tmp);
    if ($rc === 0) return ["ok" => true];
    return ["ok" => false, "error" => "write self failed (sudo): " . implode("\n", $out)];
  }

  return ["ok" => false, "error" => "write self failed"];
}

// 設定用のAPI
function action_config_get(array $APP_CONFIG): void
{
  header("Content-Type: application/json; charset=utf-8");
  echo json_encode(
    [
      "ok" => true,
      "hasPassword" => !empty($APP_CONFIG["PASSWORD_HASH"]),
      "ipAllow" => $APP_CONFIG["IP_ALLOW"],
      "clientIp" => client_ip(),
      "runAsRoot" => !empty($APP_CONFIG["RUN_AS_ROOT"]),
      "serverUser" => app_web_user(),
    ],
    JSON_UNESCAPED_UNICODE
  );
  exit();
}

function action_config_set(array $APP_CONFIG): void
{
  header("Content-Type: application/json; charset=utf-8");

  // POST必須のエンドポイントなのでCSRFを強制
  require_csrf();

  $raw = file_get_contents("php://input");
  $j = json_decode($raw, true);
  if (!is_array($j)) {
    echo json_encode(["ok" => false, "error" => "bad json"], JSON_UNESCAPED_UNICODE);
    exit();
  }

  $type = (string) ($j["change"] ?? "");

  // パスワード設定用
  if ($type === "password") {
    $npw = (string) ($j["newPassword"] ?? "");
    if ($npw === "") {
      echo json_encode(
        ["ok" => false, "error" => "新しいパスワードが空です"],
        JSON_UNESCAPED_UNICODE
      );
      exit();
    }
    $new = $APP_CONFIG;
    $new["PASSWORD_HASH"] = password_hash($npw, PASSWORD_DEFAULT);
    $w = cfg_write($new);
    echo json_encode(
      $w["ok"] ? ["ok" => true] : ["ok" => false, "error" => $w["error"] ?? "write failed"],
      JSON_UNESCAPED_UNICODE
    );
    exit();
  } elseif ($type === "password-clear") {
    $new = $APP_CONFIG;
    $new["PASSWORD_HASH"] = null;
    $w = cfg_write($new);
    echo json_encode(
      $w["ok"] ? ["ok" => true] : ["ok" => false, "error" => $w["error"] ?? "write failed"],
      JSON_UNESCAPED_UNICODE
    );
    exit();
  } elseif ($type === "ip") {
    $ips = $j["ipAllow"] ?? [];
    if (!is_array($ips)) {
      $ips = [];
    }

    // 正規化とか検証とか
    $norm = [];
    foreach ($ips as $rawIp) {
      $rawIp = trim((string) $rawIp);
      if ($rawIp === "" || str_starts_with($rawIp, "#")) {
        continue;
      }

      if (strpos($rawIp, "/") !== false) {
        // CIDR
        [$s, $b] = explode("/", $rawIp, 2) + [null, null];
        $ok =
          filter_var($s, FILTER_VALIDATE_IP) !== false &&
          is_numeric($b) &&
          $b >= 0 &&
          $b <= (strpos($s, ":") !== false ? 128 : 32);
        if (!$ok) {
          echo json_encode(["ok" => false, "error" => "CIDR不正: {$rawIp}"], JSON_UNESCAPED_UNICODE);
          exit();
        }
      } else {
        if (filter_var($rawIp, FILTER_VALIDATE_IP) === false) {
          echo json_encode(["ok" => false, "error" => "IP不正: {$rawIp}"], JSON_UNESCAPED_UNICODE);
          exit();
        }
      }
      $norm[] = $rawIp;
    }

    // ロックアウト防止
    $me = client_ip();
    if ($me && !is_ip_allowed($me, $norm)) {
      $norm[] = $me;
    }

    $new = $APP_CONFIG;
    $new["IP_ALLOW"] = array_values(array_unique($norm));
    $w = cfg_write($new);
    echo json_encode(
      $w["ok"]
        ? ["ok" => true, "ipAllow" => $new["IP_ALLOW"]]
        : ["ok" => false, "error" => $w["error"] ?? "write failed"],
      JSON_UNESCAPED_UNICODE
    );
    exit();
  } elseif ($type === "run-as-root") {
    $enabled = !empty($j["enabled"]);
    $new = $APP_CONFIG;
    $new["RUN_AS_ROOT"] = (bool)$enabled;
    $w = cfg_write($new);
    echo json_encode(
      $w["ok"] ? ["ok" => true, "runAsRoot" => $new["RUN_AS_ROOT"]] : ["ok" => false, "error" => $w["error"] ?? "write failed"],
      JSON_UNESCAPED_UNICODE
    );
    exit();
  } else {
    echo json_encode(["ok" => false, "error" => "unknown change"], JSON_UNESCAPED_UNICODE);
    exit();
  }
}

// CSRF攻撃対策
function csrf_token(): string
{
  if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }
  if (empty($_SESSION['atkfm_csrf'])) {
    $_SESSION['atkfm_csrf'] = bin2hex(random_bytes(32));
  }
  $val = $_SESSION['atkfm_csrf'];
  $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on');
  @setcookie(
    'ATKFM_CSRF',
    $val,
    [
      'path'     => '/',
      'secure'   => $secure,
      'httponly' => false,
      'samesite' => 'Strict',
    ]
  );
  return $val;
}

// POST時のCSRF攻撃対策
function require_csrf(): void
{
  $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
  if (strtoupper($method) !== 'POST') return;

  if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }
  $h  = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
  $ck = $_COOKIE['ATKFM_CSRF'] ?? '';
  $ss = $_SESSION['atkfm_csrf'] ?? '';

  if ($h === '' || $ck === '' || $ss === '' || !hash_equals($h, $ck) || !hash_equals($h, $ss)) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok'=>false,'error'=>'bad csrf token']);
    exit();
  }
}

// 認証
auth_gate($APP_CONFIG);

if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }
csrf_token();

// root権限実行時の関数
function app_run_as_root_enabled(): bool
{
  global $APP_CONFIG;
  return !empty($APP_CONFIG['RUN_AS_ROOT']);
}

function app_web_user(): string
{
  if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
    $u = @posix_getpwuid(@posix_geteuid());
    if (is_array($u) && !empty($u['name'])) return (string)$u['name'];
  }
  $env = getenv('APACHE_RUN_USER') ?: (getenv('USER') ?: '');
  if ($env !== '') return $env;
  return current_user_name() ?: 'apache';
}

function sudo_prefix(): string
{
  if (!app_run_as_root_enabled()) return '';
  return 'sudo -n ';
}

function exec_sudo(string $cmd, array &$out = null, int &$rc = null): void
{
  $out = [];
  $rc  = 0;
  @exec(sudo_prefix() . $cmd, $out, $rc);
}

function proc_open_sudo_linux(string $cmd, array $descriptorspec, array &$pipes, ?string $cwd = null, ?array $env = null)
{
  if (app_run_as_root_enabled()) {
    $cmd = 'sudo -n ' . $cmd;
  }
  return @proc_open($cmd, $descriptorspec, $pipes, $cwd, $env);
}
// root権限によるATK-FM操作
function root_fs_write(string $path, string $data, bool $append = false): bool
{
  $flags = $append ? FILE_APPEND : 0;
  $ok = @file_put_contents($path, $data, $flags | LOCK_EX);
  if ($ok !== false) return true;

  if (!app_run_as_root_enabled()) return false;

  $tmp = @tempnam(sys_get_temp_dir(), 'atkfm_w_');
  if ($tmp === false) return false;
  $w = @file_put_contents($tmp, $data);
  if ($w === false) { @unlink($tmp); return false; }

  $cmd = 'install -m 0644 ' . escapeshellarg($tmp) . ' ' . escapeshellarg($path);
  $out = []; $rc = 0; exec_sudo($cmd, $out, $rc);
  @unlink($tmp);
  return $rc === 0;
}

function root_fs_mkdir(string $dir, int $mode = 0705, bool $recursive = true): bool
{
  if (@mkdir($dir, $mode, $recursive)) return true;
  if (!app_run_as_root_enabled()) return false;

  $perm = sprintf('%o', $mode & 0777);
  $cmd = 'mkdir -p ' . escapeshellarg($dir) . ' && chmod ' . $perm . ' ' . escapeshellarg($dir);
  $out = []; $rc = 0; exec_sudo($cmd, $out, $rc);
  return $rc === 0;
}

function root_fs_unlink(string $path): bool
{
  if (@unlink($path)) return true;
  if (!app_run_as_root_enabled()) return false;

  $out = []; $rc = 0; exec_sudo('rm -f ' . escapeshellarg($path) . ' 2>&1', $out, $rc);
  return $rc === 0;
}

function root_fs_rmdir_recursive(string $dir): bool
{
  if (remove_directory($dir)) return true;
  if (!app_run_as_root_enabled()) return false;

  $out = []; $rc = 0; exec_sudo('rm -rf ' . escapeshellarg($dir) . ' 2>&1', $out, $rc);
  return $rc === 0;
}

function root_fs_rename(string $old, string $new): bool
{
  if (@rename($old, $new)) return true;
  if (!app_run_as_root_enabled()) return false;

  $out = []; $rc = 0; exec_sudo('mv -f ' . escapeshellarg($old) . ' ' . escapeshellarg($new) . ' 2>&1', $out, $rc);
  return $rc === 0;
}

function root_fs_copy(string $src, string $dst): bool
{
  if (is_dir($src)) {
    if (dir_copy($src, $dst)) return true;
    if (!app_run_as_root_enabled()) return false;
    $out = []; $rc = 0; exec_sudo('cp -a ' . escapeshellarg($src) . ' ' . escapeshellarg($dst) . ' 2>&1', $out, $rc);
    return $rc === 0;
  } else {
    if (@copy($src, $dst)) return true;
    if (!app_run_as_root_enabled()) return false;
    $out = []; $rc = 0; exec_sudo('cp -f ' . escapeshellarg($src) . ' ' . escapeshellarg($dst) . ' 2>&1', $out, $rc);
    return $rc === 0;
  }
}

function root_fs_read(string $path) // string|false
{
  $r = @file_get_contents($path);
  if ($r !== false) return $r;
  if (!app_run_as_root_enabled()) return false;

  $out = []; $rc = 0; exec_sudo('cat ' . escapeshellarg($path) . ' 2>/dev/null', $out, $rc);
  if ($rc !== 0) return false;
  return implode("\n", $out);
}

function root_fs_md5(string $path) // string|false
{
  $h = @md5_file($path);
  if ($h !== false) return $h;
  if (!app_run_as_root_enabled()) return false;

  $out = []; $rc = 0; exec_sudo('md5sum ' . escapeshellarg($path) . ' 2>/dev/null', $out, $rc);
  if ($rc !== 0 || empty($out)) return false;
  $first = trim($out[0]);
  $sp = strpos($first, ' ');
  return $sp === false ? $first : substr($first, 0, $sp);
}

function root_fs_move_uploaded(string $tmp, string $dest): bool
{
  if (@move_uploaded_file($tmp, $dest)) return true;
  if (!app_run_as_root_enabled()) return false;

  $out = []; $rc = 0; exec_sudo('install -m 0644 ' . escapeshellarg($tmp) . ' ' . escapeshellarg($dest) . ' 2>&1', $out, $rc);
  return $rc === 0;
}


// ターミナルの場合だけ先に処理
if (isset($_GET['action']) && str_starts_with((string)$_GET['action'], 'term-')) {
  header("Content-Type: application/json; charset=utf-8");
  // POST は CSRF 必須
  if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') { require_csrf(); }
  try {
    $act = (string)$_GET['action'];
    if ($act === 'term-open') {
      $label = (string)($_POST['label'] ?? '');
      echo json_encode(term_open($label), JSON_UNESCAPED_UNICODE);
    } elseif ($act === 'term-list') {
      echo json_encode(term_list(), JSON_UNESCAPED_UNICODE);
    } elseif ($act === 'term-history') {
      $sid = (string)($_GET['sid'] ?? '');
      echo json_encode(term_history($sid), JSON_UNESCAPED_UNICODE);
    } elseif ($act === 'term-run') {
      $raw = file_get_contents('php://input');
      $j   = json_decode($raw, true);
      $sid = (string)($j['sid']  ?? '');
      $inp = (string)($j['input']?? '');
      $cols= (int)   ($j['cols'] ?? 120);
      $rows= (int)   ($j['rows'] ?? 30);
      echo json_encode(term_run($sid, $inp, $cols, $rows), JSON_UNESCAPED_UNICODE);
    } elseif ($act === 'term-interrupt') {
      $raw = file_get_contents('php://input');
      $j   = json_decode($raw, true);
      $sid = (string)($j['sid'] ?? '');
      echo json_encode(term_interrupt($sid), JSON_UNESCAPED_UNICODE);
    } elseif ($act === 'term-delete') {
      $sid = (string)($_POST['sid'] ?? '');
      echo json_encode(term_delete($sid), JSON_UNESCAPED_UNICODE);
    } else {
      http_response_code(400);
      echo json_encode(['ok'=>false,'error'=>'unknown action'], JSON_UNESCAPED_UNICODE);
    }
  } catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>$e->getMessage()], JSON_UNESCAPED_UNICODE);
  }
  exit();
}

// 簡易ルーティング
if (isset($_GET["action"])) {
  header("Content-Type: application/json; charset=utf-8");
  try {
    switch ($_GET["action"]) {
      case "summary":
        echo json_encode(summary_payload(), JSON_UNESCAPED_UNICODE);
        break;
      case "processes":
        echo json_encode(processes_payload(), JSON_UNESCAPED_UNICODE);
        break;
      case "signal":
        $pid = isset($_GET["pid"]) ? intval($_GET["pid"]) : 0;
        $sig = isset($_GET["sig"]) ? strtoupper($_GET["sig"]) : "";
        echo json_encode(signal_process($pid, $sig), JSON_UNESCAPED_UNICODE);
        break;
      case "config-get":
        action_config_get($APP_CONFIG);
        break;
      case "config-set":
        action_config_set($APP_CONFIG);
        break;

      case "term2-list":
        header("Content-Type: application/json; charset=utf-8");
        echo json_encode(term2_list(), JSON_UNESCAPED_UNICODE);
        break;

      case "term2-open":
        if (function_exists('require_csrf')) { require_csrf(); }
        header("Content-Type: application/json; charset=utf-8");
        $cols = isset($_POST['cols']) ? max(20, (int)$_POST['cols']) : 120;
        $rows = isset($_POST['rows']) ? max(10, (int)$_POST['rows']) : 30;
        echo json_encode(term2_open($cols, $rows), JSON_UNESCAPED_UNICODE);
        break;

      case "term2-write":
        if (function_exists('require_csrf')) { require_csrf(); }
        header("Content-Type: application/json; charset=utf-8");
        $raw = file_get_contents("php://input");
        $j = json_decode($raw, true);
        $sid = (string)($j['sid'] ?? '');
        $b64 = (string)($j['data_b64'] ?? '');
        echo json_encode(term2_write($sid, $b64), JSON_UNESCAPED_UNICODE);
        break;

      case "term2-read":
        header("Content-Type: application/json; charset=utf-8");
        $sid = (string)($_GET['sid'] ?? '');
        echo json_encode(term2_read($sid), JSON_UNESCAPED_UNICODE);
        break;

      case "term2-resize":
        if (function_exists('require_csrf')) { require_csrf(); }
        header("Content-Type: application/json; charset=utf-8");
        $raw = file_get_contents("php://input");
        $j = json_decode($raw, true);
        $sid = (string)($j['sid'] ?? '');
        $cols = max(20, (int)($j['cols'] ?? 120));
        $rows = max(10, (int)($j['rows'] ?? 30));
        echo json_encode(term2_resize($sid, $cols, $rows), JSON_UNESCAPED_UNICODE);
        break;

      case "term2-close":
        if (function_exists('require_csrf')) { require_csrf(); }
        header("Content-Type: application/json; charset=utf-8");
        $sid = (string)($_POST['sid'] ?? '');
        echo json_encode(term2_close($sid), JSON_UNESCAPED_UNICODE);
        break;

      default:
        http_response_code(400);
        echo json_encode(["ok" => false, "error" => "unknown action"]);
    }
  } catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(["ok" => false, "error" => $e->getMessage()]);
  }
  exit();
}
// ATK-FM用のエンドポイント
if (isset($_GET["ajax-typeof"]) || isset($_GET["ajaxtypeof"])) {
  $cmd = $_GET["ajax-typeof"] ?? $_GET["ajaxtypeof"];
  $opt = $_GET["ajax-option"] ?? ($_GET["ajaxoption"] ?? "");
  $opt2 = $_GET["ajax-option2"] ?? ($_GET["ajaxoption2"] ?? "");

  if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
  }
  if (empty($_SESSION["cd"])) {
    $_SESSION["cd"] =
      rtrim(realpath("."), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
  }

  $opt = is_string($opt) ? $opt : "";
  $opt2 = is_string($opt2) ? $opt2 : "";

  try {
    switch ($cmd) {
      case "get-directory":
      case "getdirectory":
        header("Content-Type: application/json; charset=utf-8");
        $dir = $opt;
        if ($dir === "") {
          $dir = $_SESSION["cd"];
        }
        if (substr($dir, -1) !== DIRECTORY_SEPARATOR && !is_file($dir)) {
          $dir .= DIRECTORY_SEPARATOR;
        }

        // ZIPの内部閲覧
        if (is_file(rtrim($dir, DIRECTORY_SEPARATOR)) && preg_match('/\.(zip|7z)$/i', $dir)) {
          $zipPath = rtrim($dir, DIRECTORY_SEPARATOR);
          $src = $zipPath;
          if (!is_readable($zipPath) && app_run_as_root_enabled()) {
            $tmp = tempnam(sys_get_temp_dir(), 'atkfm_zip_');
            $out=[]; $rc=0;
            exec_sudo('cp -f '.escapeshellarg($zipPath).' '.escapeshellarg($tmp).' 2>&1', $out, $rc);
            if ($rc===0) { $src = $tmp; } else { @unlink($tmp); }
          }
          $list = zip_list_virtual($src);
          if ($src !== $zipPath) { @unlink($src); }
          if ($list === null) {
            echo json_encode(["atk-fm-error"=>"(ファイル/ディレクトリは存在しません)"], JSON_UNESCAPED_UNICODE);
            break;
          }
          $_SESSION["cd"] = realpath(rtrim($dir, DIRECTORY_SEPARATOR)) ?: $_SESSION["cd"];
          $ret = [];
          foreach ($list as $p) { $ret[$p] = "d"; }
          echo json_encode($ret, JSON_UNESCAPED_UNICODE);
          break;
        }

        if (is_dir($dir)) {
          $glob = @glob($dir . "{*,.*}", GLOB_BRACE);
          $out = [];
          if ($glob) {
            foreach ($glob as $p) {
              if (in_array(basename($p), [".", ".."], true)) continue;
              if (is_dir($p)) {
                $out[$p] = "b";
              } elseif (is_file($p)) {
                $ext = strtolower(pathinfo($p, PATHINFO_EXTENSION));
                if (in_array($ext, ["zip","7z","rar","gz","bz2","lzh"], true)) { $out[$p] = "c";
                } elseif ($ext === "atkfm-link") { $out[$p] = "e";
                } elseif ($ext === "atkfm-encrypt") { $out[$p] = "f";
                } else { $out[$p] = "a"; }
              }
            }
          } else if (app_run_as_root_enabled()) {
            $outLines=[]; $rc=0;
            exec_sudo('find '.escapeshellarg(rtrim($dir, DIRECTORY_SEPARATOR)).' -maxdepth 1 -mindepth 1 -printf "%p\t%y\n" 2>/dev/null', $outLines, $rc);
            $out = [];
            if ($rc===0) {
              foreach ($outLines as $ln) {
                [$p,$t] = array_map('trim', explode("\t", $ln, 2)+['','']);
                if ($p==='' || preg_match('#/(?:\.|\.\.)$#', $p)) continue;
                if ($t==='d') {
                  $out[$p] = "b";
                } elseif ($t==='f') {
                  $ext = strtolower(pathinfo($p, PATHINFO_EXTENSION));
                  if (in_array($ext, ["zip","7z","rar","gz","bz2","lzh"], true)) { $out[$p] = "c";
                  } elseif ($ext === "atkfm-link") { $out[$p] = "e";
                  } elseif ($ext === "atkfm-encrypt") { $out[$p] = "f";
                  } else { $out[$p] = "a"; }
                }
              }
            }
          }
          $_SESSION["cd"] = realpath($dir) ?: $_SESSION["cd"];
          if (empty($out)) $out = ["atk-fm-error"=>"(ファイル/ディレクトリは存在しません)"];
          echo json_encode($out, JSON_UNESCAPED_UNICODE);
          break;
        }

        // ここまでで取れなければsudoでも不可
        if (app_run_as_root_enabled()) {
          $chk=[]; $rc=0;
          exec_sudo('test -d '.escapeshellarg($dir), $chk, $rc);
          if ($rc!==0) {
            echo json_encode(["atk-fm-error"=>"指定されたディレクトリが存在しない、又はアクセスが拒否されました。"], JSON_UNESCAPED_UNICODE);
            break;
          }
          // sudo findで列挙
          $outLines=[]; $rc=0;
          exec_sudo('find '.escapeshellarg(rtrim($dir, DIRECTORY_SEPARATOR)).' -maxdepth 1 -mindepth 1 -printf "%p\t%y\n" 2>/dev/null', $outLines, $rc);
          $out = [];
          if ($rc===0) {
            foreach ($outLines as $ln) {
              [$p,$t] = array_map('trim', explode("\t", $ln, 2)+['','']);
              if ($p==='' || preg_match('#/(?:\.|\.\.)$#', $p)) continue;
              if ($t==='d') {
                $out[$p] = "b";
              } elseif ($t==='f') {
                $ext = strtolower(pathinfo($p, PATHINFO_EXTENSION));
                if (in_array($ext, ["zip","7z","rar","gz","bz2","lzh"], true)) { $out[$p] = "c";
                } elseif ($ext === "atkfm-link") { $out[$p] = "e";
                } elseif ($ext === "atkfm-encrypt") { $out[$p] = "f";
                } else { $out[$p] = "a"; }
              }
            }
          }
          $_SESSION["cd"] = rtrim($dir, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
          if (empty($out)) $out = ["atk-fm-error"=>"(ファイル/ディレクトリは存在しません)"];
          echo json_encode($out, JSON_UNESCAPED_UNICODE);
          break;
        }

        echo json_encode(["atk-fm-error"=>"指定されたディレクトリが存在しない、又はアクセスが拒否されました。"], JSON_UNESCAPED_UNICODE);
        break;

      case "get-item":
      case "getitem":
        if (!file_exists($opt) && app_run_as_root_enabled()) {
          $out=[]; $rc=0; exec_sudo('test -e '.escapeshellarg($opt), $out, $rc);
          if ($rc!==0) { http_response_code(404); echo "エラー: ファイルが見つかりません。"; break; }
        } elseif (!file_exists($opt)) {
          http_response_code(404); echo "エラー: ファイルが見つかりません。"; break;
        }
        if (isset($_GET["accept"])) {
          $mime = $_GET["accept"];
          header("Content-Type: " . $mime);
          if (is_readable($opt)) {
            header("Content-Length: " . filesize($opt));
            header('Content-Disposition: inline; filename="' . basename($opt) . '"');
            while (ob_get_level()) { ob_end_clean(); }
            readfile($opt);
          } else if (app_run_as_root_enabled()) {
            header('Content-Disposition: inline; filename="'.basename($opt).'"');
            while (ob_get_level()) { ob_end_clean(); }
            $des = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
            $p = proc_open_sudo_linux('cat '.escapeshellarg($opt), $des, $pipes, null, null);
            if (is_resource($p)) {
              fclose($pipes[0]);
              fpassthru($pipes[1]);
              fclose($pipes[1]); fclose($pipes[2]); proc_close($p);
            } else {
              echo "読み込みに失敗しました。";
            }
          } else {
            echo "ファイルを読み込めませんでした。";
          }
          break;
        }
        $viewPath = $opt;
        if (!is_readable($opt) && app_run_as_root_enabled()) {
          $tmp = tempnam(sys_get_temp_dir(), 'atkfm_view_');
          $out=[]; $rc=0; exec_sudo('cp -f '.escapeshellarg($opt).' '.escapeshellarg($tmp).' 2>&1', $out, $rc);
          if ($rc===0) { $viewPath = $tmp; }
        }
        ViewNotePad($viewPath);
        if ($viewPath !== $opt) { @unlink($viewPath); }
        break;

      case "get-item-pre":
      case "getitempre":
        header("Content-Type: text/html; charset=utf-8");
        if (!file_exists($opt) && app_run_as_root_enabled()) {
          $out=[]; $rc=0; exec_sudo('test -e '.escapeshellarg($opt), $out, $rc);
          if ($rc!==0) { echo "エラー: ファイルが見つかりません。"; break; }
        } elseif (!file_exists($opt)) {
          echo "エラー: ファイルが見つかりません。"; break;
        }
        $txt = @file_get_contents($opt);
        if ($txt === false && app_run_as_root_enabled()) {
          $lines=[]; $rc=0; exec_sudo('cat '.escapeshellarg($opt).' 2>/dev/null', $lines, $rc);
          $txt = ($rc===0) ? implode("\n", $lines) : '';
        }
        echo "<pre>".htmlspecialchars($txt, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8")."</pre>";
        break;

      case "get-linkto":
      case "getlinkto":
        header("Content-Type: text/plain; charset=utf-8");
        if (is_file($opt) && is_readable($opt)) {
          echo rawurlencode((string)@file_get_contents($opt));
        } elseif (app_run_as_root_enabled()) {
          $lines=[]; $rc=0; exec_sudo('cat '.escapeshellarg($opt).' 2>/dev/null', $lines, $rc);
          echo ($rc===0) ? rawurlencode(implode("\n",$lines)) : "";
        } else {
          echo "";
        }
        break;

      case "view-html":
      case "viewhtml":
        header("Content-Type: text/html; charset=utf-8");
        if (!file_exists($opt) && app_run_as_root_enabled()) {
          $out=[]; $rc=0; exec_sudo('test -e '.escapeshellarg($opt), $out, $rc);
          if ($rc!==0) { echo "エラー: ファイルが見つかりません。"; break; }
        } elseif (!file_exists($opt)) {
          echo "エラー: ファイルが見つかりません。"; break;
        }
        $base = $opt2 ? "<base href=\"".htmlspecialchars($opt2, ENT_QUOTES)."\">\n" : "";
        $html = @file_get_contents($opt);
        if ($html === false && app_run_as_root_enabled()) {
          $lines=[]; $rc=0; exec_sudo('cat '.escapeshellarg($opt).' 2>/dev/null', $lines, $rc);
          $html = ($rc===0) ? implode("\n",$lines) : "エラー: 読み込み失敗";
        }
        echo $base . (string)$html;
        break;

      case "view-hex":
      case "viewhex":
        header("Content-Type: text/html; charset=utf-8");
        if (!file_exists($opt) && app_run_as_root_enabled()) {
          $o=[]; $rc=0; exec_sudo('test -e '.escapeshellarg($opt), $o, $rc);
          if ($rc!==0) { echo "エラー: ファイルが見つかりません。"; break; }
        } elseif (!file_exists($opt)) { echo "エラー: ファイルが見つかりません。"; break; }
        $tgt = $opt;
        if (!is_readable($opt) && app_run_as_root_enabled()) {
          $tmp = tempnam(sys_get_temp_dir(), 'atkfm_hex_');
          $o=[]; $rc=0; exec_sudo('cp -f '.escapeshellarg($opt).' '.escapeshellarg($tmp).' 2>&1', $o, $rc);
          if ($rc===0) $tgt = $tmp;
        }
        hex_dump_html($tgt);
        if ($tgt !== $opt) { @unlink($tgt); }
        break;

      case "remove-directory":
      case "removedirectory":
        header("Content-Type: text/plain; charset=utf-8");
        if (!file_exists($opt)) { echo "Error: 指定されたディレクトリは存在しません。"; break; }
        if (remove_directory($opt)) { echo "ディレクトリを削除しました。"; break; }
        if (app_run_as_root_enabled()) {
          $out=[]; $rc=0; exec_sudo('rm -rf '.escapeshellarg($opt).' 2>&1', $out, $rc);
          echo ($rc===0) ? "ディレクトリを削除しました。" : "Error: 削除に失敗しました。";
        } else {
          echo "Error: 削除に失敗しました。";
        }
        break;

      case "remove-item":
      case "removeitem":
        header("Content-Type: text/plain; charset=utf-8");
        if (@unlink($opt)) { echo ""; break; }
        if (app_run_as_root_enabled()) {
          $out=[]; $rc=0; exec_sudo('rm -f '.escapeshellarg($opt).' 2>&1', $out, $rc);
          echo ($rc===0) ? "" : "Error: 指定されたファイルを削除できません。";
        } else {
          echo "Error: 指定されたファイルを削除できません。";
        }
        break;

      case "download-item":
      case "downloaditem":
        if (!file_exists($opt) && app_run_as_root_enabled()) {
          $o=[]; $rc=0; exec_sudo('test -e '.escapeshellarg($opt), $o, $rc);
          if ($rc!==0) { echo "ファイルを読み込めませんでした。"; break; }
        } elseif (!is_readable($opt)) {
          if (!app_run_as_root_enabled()) { echo "ファイルを読み込めませんでした。"; break; }
        }
        header("Content-Type: application/octet-stream");
        header("X-Content-Type-Options: nosniff");
        header('Content-Disposition: attachment; filename="'.basename($opt).'"');
        while (ob_get_level()) { ob_end_clean(); }
        if (is_readable($opt)) {
          header("Content-Length: " . filesize($opt));
          readfile($opt);
        } else {
          $des=[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
          $p = proc_open_sudo_linux('cat '.escapeshellarg($opt), $des, $pipes, null, null);
          if (is_resource($p)) {
            fclose($pipes[0]);
            fpassthru($pipes[1]);
            fclose($pipes[1]); fclose($pipes[2]); proc_close($p);
          } else {
            echo "読み込みに失敗しました。";
          }
        }
        break;

      case "upload-item":
      case "uploaditem":
        header("Content-Type: text/plain; charset=utf-8");
        $errors = [];
        if (!isset($_FILES["file"])) { echo "アップロード対象がありません。"; break; }
        $count = is_array($_FILES["file"]["name"]) ? count($_FILES["file"]["name"]) : 0;
        for ($i=0; $i<$count; $i++) {
          if (is_uploaded_file($_FILES["file"]["tmp_name"][$i])) {
            $dest = rtrim($_SESSION["cd"], DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.basename($_FILES["file"]["name"][$i]);
            // まずは自前の一時領域に移動
            $tmp = tempnam(sys_get_temp_dir(), 'atkfm_up_');
            if (!@move_uploaded_file($_FILES["file"]["tmp_name"][$i], $tmp)) {
              $errors[] = $_FILES["file"]["name"][$i] . " をアップロードできませんでした。";
              continue;
            }
            // 上書きできない場合はsudoでコピー
            if (@copy($tmp, $dest) === false) {
              if (app_run_as_root_enabled()) {
                $out=[]; $rc=0; exec_sudo('install -m 0644 -D '.escapeshellarg($tmp).' '.escapeshellarg($dest).' 2>&1', $out, $rc);
                if ($rc!==0) $errors[] = $_FILES["file"]["name"][$i] . " をアップロードできませんでした。";
              } else {
                $errors[] = $_FILES["file"]["name"][$i] . " をアップロードできませんでした。";
              }
            }
            @unlink($tmp);
          }
        }
        echo empty($errors) ? "ファイルをアップロードしました。" : implode("\n", $errors);
        break;

      case "min-upload-item":
      case "minuploaditem":
        header("Content-Type: application/json; charset=utf-8");
        if ($opt === "remove-upload-info" && isset($_POST["FileName"])) {
          $jsonname = rtrim($_SESSION["cd"], DIRECTORY_SEPARATOR)."/_upload-beacon_".basename($_POST["FileName"]).".json.atkfmbeacon";
          $ok = @unlink($jsonname);
          if (!$ok && app_run_as_root_enabled()) {
            $out=[];$rc=0; exec_sudo('rm -f '.escapeshellarg($jsonname).' 2>&1', $out, $rc);
            $ok = ($rc===0);
          }
          echo json_encode($ok ? "" : "error", JSON_UNESCAPED_UNICODE);
          break;
        }
        if (!isset($_POST["filename"]) || !isset($_FILES["data"])) {
          echo json_encode(["error"=>"missing fields"]); break;
        }
        $dest = rtrim($_SESSION["cd"], DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.basename($_POST["filename"]);
        $tmp = $_FILES["data"]["tmp_name"];
        $ok = @file_put_contents($dest, file_get_contents($tmp), FILE_APPEND);
        if ($ok === false && app_run_as_root_enabled()) {
          // 一旦tmpにコピーして cat >> で追記
          $chunkTmp = tempnam(sys_get_temp_dir(), 'atkfm_chunk_');
          @copy($tmp, $chunkTmp);
          $out=[]; $rc=0; exec_sudo('sh -lc "cat '.escapeshellarg($chunkTmp).' >> '.escapeshellarg($dest).'" 2>&1', $out, $rc);
          @unlink($chunkTmp);
        }
        echo json_encode(["size" => @filesize($dest)], JSON_UNESCAPED_UNICODE);
        break;

      case "uploadfromurl":
        header("Content-Type: text/plain; charset=utf-8");
        $fn = basename(parse_url($opt, PHP_URL_PATH) ?: "NoName.txt");
        $dest = rtrim($_SESSION["cd"], DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.substr($fn, 0, 120);
        // まずは一時ファイルにダウンロード
        $tmp = tempnam(sys_get_temp_dir(), 'atkfm_dl_');
        download($opt, $tmp);
        if (@copy($tmp, $dest) === false && app_run_as_root_enabled()) {
          $out=[]; $rc=0; exec_sudo('install -m 0644 -D '.escapeshellarg($tmp).' '.escapeshellarg($dest).' 2>&1', $out, $rc);
        }
        @unlink($tmp);
        echo "URLから{$dest}をアップロードしました。";
        break;

      case "add-item":
      case "additem":
        header("Content-Type: text/plain; charset=utf-8");
        $dest = rtrim($_SESSION["cd"], DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$opt;
        $ok = (@file_put_contents($dest, "") !== false);
        if (!$ok && app_run_as_root_enabled()) {
          $out=[]; $rc=0; exec_sudo('sh -lc "umask 022; : > '.escapeshellarg($dest).'" 2>&1', $out, $rc);
          $ok = ($rc===0);
        }
        echo $ok ? "1" : "0";
        break;

      case "create-link":
      case "createlink":
        header("Content-Type: text/plain; charset=utf-8");
        $content = rtrim($_SESSION["cd"], DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
        $ok = (@file_put_contents($opt, $content) !== false);
        if (!$ok && app_run_as_root_enabled()) {
          $tmp = tempnam(sys_get_temp_dir(), 'atkfm_link_');
          @file_put_contents($tmp, $content);
          $out=[]; $rc=0; exec_sudo('install -m 0644 -D '.escapeshellarg($tmp).' '.escapeshellarg($opt).' 2>&1', $out, $rc);
          @unlink($tmp);
          $ok = ($rc===0);
        }
        echo $ok ? "1" : "0";
        break;

      case "add-directory":
      case "adddirectory":
        header("Content-Type: text/plain; charset=utf-8");
        $dest = rtrim($_SESSION["cd"], DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.rtrim($opt, DIRECTORY_SEPARATOR);
        @mkdir($dest, 0705, true);
        if (!is_dir($dest) && app_run_as_root_enabled()) {
          $out=[]; $rc=0; exec_sudo('mkdir -p '.escapeshellarg($dest).' 2>&1', $out, $rc);
        }
        echo "";
        break;

      case "open-zip":
      case "openzip":
        header("Content-Type: text/plain; charset=utf-8");
        $zip = new ZipArchive();
        $okPHP = ($zip->open($opt) === true);
        $unzip_dir = rtrim($_SESSION["cd"], DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.pathinfo($opt, PATHINFO_FILENAME);
        if ($okPHP) {
          @mkdir($unzip_dir, 0755, true);
          $ok = @$zip->extractTo($unzip_dir);
          $zip->close();
          if ($ok) { echo "展開に成功しました!({$unzip_dir})"; break; }
        }
        if (app_run_as_root_enabled()) {
          $out=[]; $rc=0;
          exec_sudo('sh -lc "umask 022; mkdir -p '.escapeshellarg($unzip_dir).'; (unzip -o '.escapeshellarg($opt).' -d '.escapeshellarg($unzip_dir).' || 7z x -y '.escapeshellarg($opt).' -o'.escapeshellarg($unzip_dir).')" 2>&1', $out, $rc);
          echo ($rc===0) ? "展開に成功しました!({$unzip_dir})" : "ファイルの展開に失敗しました。";
        } else {
          echo "ファイルの展開に失敗しました。";
        }
        break;

      case "make-zip":
      case "makezip":
        header("Content-Type: text/plain; charset=utf-8");
        $ok = zipDirectory($opt, $opt . ".zip");
        if (!$ok && app_run_as_root_enabled()) {
          $dir = $opt;
          $parent = dirname($dir);
          $base = basename($dir);
          $out=[]; $rc=0;
          exec_sudo('sh -lc "cd '.escapeshellarg($parent).' && zip -r '.escapeshellarg($base.'.zip').' '.escapeshellarg($base).'" 2>&1', $out, $rc);
          $ok = ($rc===0);
        }
        echo $ok ? "フォルダーを圧縮しました。" : "圧縮に失敗しました。";
        break;

      case "copy-item":
      case "copyitem":
        header("Content-Type: text/plain; charset=utf-8");
        if (is_dir($opt)) {
          $dest = $opt . " (コピー)";
          $ok = dir_copy($opt, $dest);
          if (!$ok && app_run_as_root_enabled()) {
            $out=[]; $rc=0; exec_sudo('cp -a '.escapeshellarg($opt).' '.escapeshellarg($dest).' 2>&1', $out, $rc);
            $ok = ($rc===0);
          }
          echo $ok ? "OK" : "NG";
        } else {
          $ok = @copy($opt, $opt . " (コピー)");
          if (!$ok && app_run_as_root_enabled()) {
            $out=[]; $rc=0; exec_sudo('cp -f '.escapeshellarg($opt).' '.escapeshellarg($opt . " (コピー)").' 2>&1', $out, $rc);
            $ok = ($rc===0);
          }
          echo $ok ? "OK" : "NG";
        }
        break;

      case "rename-item":
      case "renameitem":
        header("Content-Type: text/plain; charset=utf-8");
        $ok = @rename($opt, $opt2);
        if (!$ok && app_run_as_root_enabled()) {
          $out=[]; $rc=0; exec_sudo('mv -f '.escapeshellarg($opt).' '.escapeshellarg($opt2).' 2>&1', $out, $rc);
          $ok = ($rc===0);
        }
        echo $ok ? "1" : "0";
        break;

      case "count-directory-files":
      case "countdirectoryfiles":
        header("Content-Type: application/json; charset=utf-8");

        $saved_cd = $_SESSION["cd"] ?? null;
        if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }

        $start = microtime(true);
        $filesCnt = 0; $dirsCnt = 0; $sizeHuman = "0.00KB";
        if (is_dir($opt)) {
          try {
            $iter = new RecursiveIteratorIterator(
              new RecursiveDirectoryIterator($opt, FilesystemIterator::CURRENT_AS_FILEINFO | FilesystemIterator::KEY_AS_PATHNAME | FilesystemIterator::SKIP_DOTS),
              RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($iter as $path => $info) { $info->isFile() ? $filesCnt++ : $dirsCnt++; }
            $sizeHuman = used_bytes(rtrim($opt, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR);
          } catch (Throwable $e) {
            // 通常の読み取りに失敗したらsudo findで集計
            if (app_run_as_root_enabled()) {
              $o=[]; $rc=0;
              exec_sudo('find '.escapeshellarg($opt).' -type f -printf "." | wc -c', $o, $rc);
              if ($rc===0) $filesCnt = (int)trim($o[0] ?? '0');
              $o=[]; $rc=0;
              exec_sudo('find '.escapeshellarg($opt).' -type d -printf "." | wc -c', $o, $rc);
              if ($rc===0) $dirsCnt = (int)trim($o[0] ?? '0');
              $o=[]; $rc=0;
              exec_sudo('sh -lc "du -sb '.escapeshellarg($opt).' | awk \'{print $1}\'"', $o, $rc);
              if ($rc===0) $sizeHuman = used_bytes(rtrim($opt, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR);
            }
          }
        }
        echo json_encode(["File"=>$filesCnt, "Directory"=>$dirsCnt, "Time"=>microtime(true)-$start, "SIZE"=>$sizeHuman], JSON_UNESCAPED_UNICODE);
        break;

      case "get-filesize":
      case "getfilesize":
        header("Content-Type: text/plain; charset=utf-8");
        $sz = @filesize($opt);
        if ($sz === false && app_run_as_root_enabled()) {
          $o=[]; $rc=0; exec_sudo('stat -c %s '.escapeshellarg($opt).' 2>/dev/null', $o, $rc);
          if ($rc===0) $sz = (int)trim($o[0] ?? '0');
        }
        echo calcFileSize(is_numeric($sz) ? $sz : 0);
        break;

      case "save-item":
      case "saveitem":
        header("Content-Type: text/plain; charset=utf-8");
        $data = $_POST["naka"] ?? "";
        $ok = (@file_put_contents($opt, $data) !== false);
        if (!$ok && app_run_as_root_enabled()) {
          $tmp = tempnam(sys_get_temp_dir(), 'atkfm_save_');
          @file_put_contents($tmp, $data);
          $out=[]; $rc=0; exec_sudo('install -m 0644 -D '.escapeshellarg($tmp).' '.escapeshellarg($opt).' 2>&1', $out, $rc);
          @unlink($tmp);
          $ok = ($rc===0);
        }
        echo $ok ? "" : "error";
        break;

      case "get-filemd5":
      case "getfilemd5":
        header("Content-Type: text/plain; charset=utf-8");
        $h = @md5_file($opt);
        if ($h === false && app_run_as_root_enabled()) {
          $o=[]; $rc=0; exec_sudo('md5sum '.escapeshellarg($opt).' 2>/dev/null', $o, $rc);
          if ($rc===0 && !empty($o)) { $h = preg_split('/\s+/', trim($o[0]))[0] ?? ''; }
        }
        echo $h ?: "";
        break;

      case "encrypt-item":
      case "encryptitem":
        header("Content-Type: text/plain; charset=utf-8");
        $srcPath = $opt;
        $raw = @file_get_contents($srcPath);
        if ($raw === false && app_run_as_root_enabled()) {
          $tmp = tempnam(sys_get_temp_dir(), 'atkfm_enc_');
          $o=[]; $rc=0; exec_sudo('cp -f '.escapeshellarg($opt).' '.escapeshellarg($tmp).' 2>&1', $o, $rc);
          if ($rc===0) { $srcPath = $tmp; $raw = @file_get_contents($srcPath); }
        }
        $enc = ($raw === false) ? false : openssl_encrypt($raw, "aes-256-cbc", $opt2, OPENSSL_RAW_DATA, "4910857128499038");
        if ($srcPath !== $opt) { @unlink($srcPath); }
        if ($enc === false) { echo "error"; break; }
        $dest = $opt . ".atkfm-encrypt";
        $ok = (@file_put_contents($dest, "ATKFMENCRYPTFILE!" . $enc) !== false);
        if (!$ok && app_run_as_root_enabled()) {
          $tmpOut = tempnam(sys_get_temp_dir(), 'atkfm_encout_');
          @file_put_contents($tmpOut, "ATKFMENCRYPTFILE!" . $enc);
          $o=[]; $rc=0; exec_sudo('install -m 0644 -D '.escapeshellarg($tmpOut).' '.escapeshellarg($dest).' 2>&1', $o, $rc);
          @unlink($tmpOut);
          $ok = ($rc===0);
        }
        echo $ok ? $dest : "error";
        break;

      case "decrypt-item":
      case "decryptitem":
        header("Content-Type: text/plain; charset=utf-8");
        if (strtolower(pathinfo($opt, PATHINFO_EXTENSION)) !== "atkfm-encrypt") {
          echo "エラー: 拡張子が「.atkfm-encrypt」のファイルを選択してください。"; break;
        }
        $src = $opt;
        $raw = @file_get_contents($opt);
        if (($raw === false || substr($raw, 0, 16) !== "ATKFMENCRYPTFILE") && app_run_as_root_enabled()) {
          $tmp = tempnam(sys_get_temp_dir(), 'atkfm_dec_');
          $o=[]; $rc=0; exec_sudo('cp -f '.escapeshellarg($opt).' '.escapeshellarg($tmp).' 2>&1', $o, $rc);
          if ($rc===0) { $src = $tmp; $raw = @file_get_contents($src); }
        }
        if ($raw === false || substr($raw, 0, 16) !== "ATKFMENCRYPTFILE") {
          if ($src !== $opt) @unlink($src);
          echo "エラー: このファイルはATK-FMにより暗号化されていません。"; break;
        }
        $dec = openssl_decrypt(substr($raw, 17), "aes-256-cbc", $opt2, OPENSSL_RAW_DATA, "4910857128499038");
        if ($src !== $opt) @unlink($src);
        if ($dec === false) { echo "エラー: パスワードが違う、又はファイルが破損しています。"; break; }
        $dst = dirname($opt).DIRECTORY_SEPARATOR.pathinfo($opt, PATHINFO_FILENAME);
        $ok = (@file_put_contents($dst, $dec) !== false);
        if (!$ok && app_run_as_root_enabled()) {
          $tmpOut = tempnam(sys_get_temp_dir(), 'atkfm_decout_');
          @file_put_contents($tmpOut, $dec);
          $o=[]; $rc=0; exec_sudo('install -m 0644 -D '.escapeshellarg($tmpOut).' '.escapeshellarg($dst).' 2>&1', $o, $rc);
          @unlink($tmpOut);
          $ok = ($rc===0);
        }
        echo $ok ? "ファイルを複合化しました。" : "error";
        break;

      case "get-item-zip":
      case "getitemzip":
        header("Content-Type: text/plain; charset=utf-8");
        $zipSrc = rtrim($opt, DIRECTORY_SEPARATOR);
        $local = $zipSrc;
        if (!is_readable($zipSrc) && app_run_as_root_enabled()) {
          $tmp = tempnam(sys_get_temp_dir(), 'atkfm_zipr_');
          $o=[]; $rc=0; exec_sudo('cp -f '.escapeshellarg($zipSrc).' '.escapeshellarg($tmp).' 2>&1', $o, $rc);
          if ($rc===0) $local = $tmp;
        }
        $txt = zip_read_file($local, $opt2);
        if ($local !== $zipSrc) @unlink($local);
        if ($txt === null) { echo "// テキストが空です"; }
        else { echo is_utf8($txt) ? $txt : @mb_convert_encoding($txt, "UTF-8", "SJIS"); }
        break;

      case "remove-item-zip":
      case "removeitemzip":
        header("Content-Type: text/plain; charset=utf-8");
        $zipPath = rtrim($opt, DIRECTORY_SEPARATOR);
        $local = $zipPath; $needPushBack = false;
        if (!is_writable($zipPath) && app_run_as_root_enabled()) {
          $tmp = tempnam(sys_get_temp_dir(), 'atkfm_zipw_');
          $o=[]; $rc=0; exec_sudo('cp -f '.escapeshellarg($zipPath).' '.escapeshellarg($tmp).' 2>&1', $o, $rc);
          if ($rc===0) { $local = $tmp; $needPushBack = true; }
        }
        $zip = new ZipArchive();
        if ($zip->open($local) === true) {
          $ok = $zip->deleteName($opt2);
          $zip->close();
          if ($ok && $needPushBack) {
            $o=[]; $rc=0; exec_sudo('mv -f '.escapeshellarg($local).' '.escapeshellarg($zipPath).' 2>&1', $o, $rc);
            $ok = ($rc===0);
          }
          if ($local !== $zipPath && !$needPushBack) @unlink($local);
          echo $ok ? "削除に成功しました。" : "エラー: 削除に失敗しました。";
        } else {
          echo "エラー: ファイルが見つかりませんでした。";
        }
        break;

      case "list-view":
      case "listview":
        ViewListPreview($opt);
        break;

      default:
        http_response_code(404);
        echo "CommandNotFoundException";
    }

  } catch (Throwable $e) {
    http_response_code(500);
    header("Content-Type: text/plain; charset=utf-8");
    echo "ERROR: " . $e->getMessage();
  }
  exit();
}

function is_linux(): bool
{
  return stripos(PHP_OS, "Linux") !== false;
}
function is_windows(): bool
{
  return stripos(PHP_OS, "WIN") === 0 ||
    (defined("PHP_OS_FAMILY") && PHP_OS_FAMILY === "Windows");
}
function current_user_name(): string
{
  $u = '';
  if (is_windows()) {
    $u = getenv('USERNAME') ?: '';
  } else {
    $u = getenv('USER') ?: '';
    if ($u === '') {
      $out = []; $rc = 0; @exec('id -un 2>/dev/null', $out, $rc);
      if ($rc === 0 && !empty($out)) $u = trim($out[0]);
    }
  }
  if ($u === '') { $u = get_current_user() ?: 'user'; }
  return $u;
}
function which(string $cmd): ?string
{
  $out = [];
  $rc = 0;
  if (is_windows()) {
    @exec("where " . escapeshellarg($cmd), $out, $rc);
  } else {
    @exec("command -v " . escapeshellarg($cmd) . " 2>/dev/null", $out, $rc);
  }
  return $rc === 0 && !empty($out) ? trim($out[0]) : null;
}
function human_bytes_from_kb($kb): string
{
  if ($kb === null) {
    return "--";
  }
  $b = $kb * 1024.0;
  $u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  $i = 0;
  while ($b >= 1024 && $i < count($u) - 1) {
    $b /= 1024;
    $i++;
  }
  return sprintf("%.2f %s", $b, $u[$i]);
}
function human_bytes_from_bytes($b): string
{
  if ($b === null) {
    return "--";
  }
  $u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  $i = 0;
  while ($b >= 1024 && $i < count($u) - 1) {
    $b /= 1024;
    $i++;
  }
  return sprintf("%.2f %s", $b, $u[$i]);
}

// システム情報表示用のやつ
function summary_payload(): array
{
  $ts = microtime(true);
  return [
    "ok" => true,
    "timestamp" => $ts,
    "platform" => php_uname("s") . " " . php_uname("r"),
    "cpu" => cpu_times(),
    "memory" => memory_info(),
    "loadavg" => loadavg_info(),
    "gpus" => gpu_info(),
  ];
}
function cpu_times(): array
{
  if (is_linux()) {
    $lines = @file("/proc/stat", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
      return ["total" => null, "cores" => []];
    }
    $total = null;
    $cores = [];
    foreach ($lines as $ln) {
      if (strpos($ln, "cpu") !== 0) {
        continue;
      }
      $parts = preg_split("/\s+/", trim($ln));
      $key = $parts[0];
      $vals = array_map("intval", array_slice($parts, 1, 10));
      if ($key === "cpu") {
        $total = $vals;
      } elseif (preg_match('/^cpu(\d+)$/', $key, $m)) {
        $cores[(int) $m[1]] = $vals;
      }
    }
    ksort($cores);
    return [
      "model" => cpu_model_linux(),
      "total" => $total,
      "cores" => array_values($cores),
    ];
  }
  return ["model" => php_uname("m"), "total" => null, "cores" => []];
}
function cpu_model_linux(): ?string
{
  $c = @file("/proc/cpuinfo", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
  if ($c === false) {
    return null;
  }
  foreach ($c as $line) {
    if (stripos($line, "model name") === 0) {
      $p = explode(":", $line, 2);
      return isset($p[1]) ? trim($p[1]) : null;
    }
  }
  return null;
}
function memory_info(): array
{
  if (is_linux()) {
    $mi = @file("/proc/meminfo", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($mi === false) {
      return ["kb_total" => null];
    }
    $map = [];
    foreach ($mi as $ln) {
      if (strpos($ln, ":") === false) {
        continue;
      }
      [$k, $v] = explode(":", $ln, 2);
      $v = trim($v);
      $p = preg_split("/\s+/", $v);
      $map[$k] = (int) $p[0];
    }
    $total = $map["MemTotal"] ?? 0;
    $avail =
      $map["MemAvailable"] ??
      ($map["MemFree"] ?? 0) +
        ($map["Buffers"] ?? 0) +
        ($map["Cached"] ?? 0) +
        ($map["SReclaimable"] ?? 0);
    $used = max(0, $total - $avail);
    $swap_total = $map["SwapTotal"] ?? 0;
    $swap_free = $map["SwapFree"] ?? 0;
    $swap_used = max(0, $swap_total - $swap_free);
    return [
      "kb_total" => $total,
      "kb_available" => $avail,
      "kb_used" => $used,
      "swap_kb_total" => $swap_total,
      "swap_kb_used" => $swap_used,
    ];
  }
  if (is_windows()) {
    $out = [];
    $rc = 0;
    @exec(
      "wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /Value",
      $out,
      $rc
    );
    if ($rc === 0 && !empty($out)) {
      $vals = ["TotalVisibleMemorySize" => 0, "FreePhysicalMemory" => 0];
      foreach ($out as $ln) {
        $ln = trim($ln);
        if ($ln === "") {
          continue;
        }
        [$k, $v] = array_map("trim", explode("=", $ln, 2));
        if (isset($vals[$k])) {
          $vals[$k] = (int) $v;
        }
      }
      $total = $vals["TotalVisibleMemorySize"];
      $free = $vals["FreePhysicalMemory"];
      $used = max(0, $total - $free);
      return [
        "kb_total" => $total,
        "kb_available" => $free,
        "kb_used" => $used,
        "swap_kb_total" => null,
        "swap_kb_used" => null,
      ];
    }
  }
  return [
    "kb_total" => null,
    "kb_available" => null,
    "kb_used" => null,
    "swap_kb_total" => null,
    "swap_kb_used" => null,
  ];
}
function loadavg_info(): array
{
  if (is_linux()) {
    $s = @file_get_contents("/proc/loadavg");
    if ($s === false) {
      return ["1" => null, "5" => null, "15" => null];
    }
    $p = preg_split("/\s+/", trim($s));
    return ["1" => (float) $p[0], "5" => (float) $p[1], "15" => (float) $p[2]];
  }
  return ["1" => null, "5" => null, "15" => null];
}
function gpu_info(): array
{
  $g = [];
  $nvsmi = which("nvidia-smi");
  if ($nvsmi) {
    $out = [];
    $rc = 0;
    @exec(
      $nvsmi .
        " --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits",
      $out,
      $rc
    );
    if ($rc === 0) {
      foreach ($out as $ln) {
        $parts = array_map("trim", explode(",", $ln));
        if (count($parts) >= 5) {
          $g[] = [
            "vendor" => "nvidia",
            "index" => (int) $parts[0],
            "name" => $parts[1],
            "util_percent" => (int) $parts[2],
            "mem_used_mb" => (int) $parts[3],
            "mem_total_mb" => (int) $parts[4],
          ];
        }
      };
    }
  }
  return $g;
}

// サーバーアプリを取得する関数
function detect_server_app(): ?string
{
  $ss = $_SERVER["SERVER_SOFTWARE"] ?? null;
  if ($ss) {
    return $ss;
  }
  $out = [];
  $rc = 0;
  @exec("nginx -v 2>&1", $out, $rc);
  if (!empty($out) && stripos($out[0], "nginx") !== false) {
    return trim(preg_replace("/^.*?:\s*/", "", $out[0]));
  }
  $out = [];
  $rc = 0;
  @exec("apache2 -v 2>&1", $out, $rc);
  if (!empty($out) && stripos($out[0], "Server version") !== false) {
    return trim(preg_replace("/^Server version:\s*/i", "", $out[0]));
  }
  $out = [];
  $rc = 0;
  @exec("httpd -v 2>&1", $out, $rc);
  if (!empty($out) && stripos($out[0], "Server version") !== false) {
    return trim(preg_replace("/^Server version:\s*/i", "", $out[0]));
  }
  if (is_windows()) {
    return "Microsoft-IIS (detected)";
  }
  return null;
}
function static_info(): array
{
  $mem = memory_info();
  $mem_total = $mem["kb_total"] ?? null;
  $swap_total = $mem["swap_kb_total"] ?? null;

  $disk = null;
  if (is_linux() || is_windows()) {
    $size = @disk_total_space("/");
    $free = @disk_free_space("/");
    if ($size > 0) {
      $disk = [
        "target" => "/",
        "size_bytes" => $size,
        "used_bytes" => $size - $free,
        "avail_bytes" => $free,
        "used_percent" =>
          $size > 0 && $free !== false
            ? round((($size - $free) / $size) * 100) . "%"
            : null,
      ];
    }
  }

  // GPUはnvidia-smiから取得(入って無ければ諦める。NVIDIA以外のGPU？いやそんなものはGPUではありませんので)
  $gpu_list = [];
  $nvsmi = which("nvidia-smi");
  if ($nvsmi) {
    $out = [];
    $rc = 0;
    @exec($nvsmi . " --query-gpu=name --format=csv,noheader", $out, $rc);
    foreach ($out as $nm) {
      $nm = trim($nm);
      if ($nm !== "") {
        $gpu_list[] = $nm;
      }
    }
  }
  return [
    "ServerApp" => detect_server_app() ?: "Unknown",
    "PHPVersion" => PHP_VERSION . " (" . PHP_SAPI . ")",
    "Domain" => $_SERVER["HTTP_HOST"] ?? ($_SERVER["SERVER_NAME"] ?? "Unknown"),
    "OS" => php_uname("s"),
    "Host" => php_uname("n"),
    "Kernel" => php_uname("r"),
    "User" => current_user_name(),
    "Shell" => is_windows()
      ? (getenv("ComSpec") ?:
      "cmd.exe")
      : (getenv("SHELL") ?:
      "/bin/sh"),
    "CPU" => trim(cpu_model_linux() ?? php_uname("m")),
    "Memory" =>
      $mem_total !== null
        ? human_bytes_from_kb($mem_total) . " total"
        : "Unknown",
    "Swap" =>
      $swap_total !== null
        ? human_bytes_from_kb($swap_total) . " total"
        : "Unknown",
    "GPU" => !empty($gpu_list) ? implode(", ", $gpu_list) : "None detected",
    "Disk" => $disk
      ? human_bytes_from_bytes($disk["size_bytes"]) .
        " total @ " .
        ($disk["target"] ?? "/")
      : "Unknown",
  ];
}

// プロセス一覧取得
function processes_payload(): array
{
  if (is_linux()) {
    $cmd =
      "ps -eo pid=,user=,ni=,pri=,stat=,pcpu=,pmem=,rss=,etime=,comm=,command= --cols 2000";
    $lines = [];
    $rc = 0;
    @exec($cmd, $lines, $rc);
    if ($rc !== 0) {
      return ["ok" => false, "error" => "ps failed"];
    }
    $procs = [];
    foreach ($lines as $line) {
      $parts = preg_split("/\s+/", trim($line), 11);
      if (count($parts) < 10) {
        continue;
      }
      $procs[] = [
        "pid" => (int) $parts[0],
        "user" => $parts[1] ?? "",
        "nice" => (int) ($parts[2] ?? 0),
        "priority" => (int) ($parts[3] ?? 0),
        "state" => $parts[4] ?? "",
        "cpu_percent" => (float) str_replace(",", ".", $parts[5] ?? "0"),
        "mem_percent" => (float) str_replace(",", ".", $parts[6] ?? "0"),
        "rss_kb" => (int) ($parts[7] ?? 0),
        "elapsed" => $parts[8] ?? "",
        "title" => $parts[9] ?? "",
        "command" => $parts[10] ?? ($parts[9] ?? ""),
      ];
    }
    return ["ok" => true, "processes" => $procs];
  }
  // Windowsの場合
  $lines = [];
  $rc = 0;
  @exec(
    "wmic process get ProcessId,Name,WorkingSetSize,CommandLine /FORMAT:CSV",
    $lines,
    $rc
  );
  $procs = [];
  if ($rc === 0 && !empty($lines)) {
    foreach ($lines as $i => $line) {
      if ($i === 0 || trim($line) === "" || stripos($line, "Node,") === 0) {
        continue;
      }
      $cols = str_getcsv($line);
      if (count($cols) < 4) {
        continue;
      }
      $name = $cols[1] ?? "";
      $cmd = $cols[2] ?? "";
      $pid = (int) ($cols[3] ?? 0);
      $wss = (int) ($cols[4] ?? 0);
      $procs[] = [
        "pid" => $pid,
        "user" => "",
        "nice" => null,
        "priority" => null,
        "state" => "",
        "cpu_percent" => null,
        "mem_percent" => null,
        "rss_kb" => (int) round($wss / 1024),
        "elapsed" => "",
        "title" => $name,
        "command" => $cmd,
      ];
    }
  }
  return [
    "ok" => true,
    "processes" => $procs,
    "note" => "Limited fields on Windows",
  ];
}
function signal_process(int $pid, string $sig): array
{
  if ($pid <= 0) {
    return ["ok" => false, "error" => "invalid pid"];
  }
  $allowed = ["TERM", "KILL", "STOP", "CONT"];
  if (!in_array($sig, $allowed, true)) {
    return ["ok" => false, "error" => "invalid signal"];
  }
  if (is_windows()) {
    if ($sig === "KILL") {
      $cmd = "taskkill /PID " . $pid . " /F";
    } elseif ($sig === "TERM") {
      $cmd = "taskkill /PID " . $pid;
    } else {
      return ["ok" => false, "error" => "STOP/CONT not supported on Windows"];
    }
    $out = [];
    $rc = 0;
    @exec($cmd, $out, $rc);
    return $rc === 0
      ? ["ok" => true, "message" => implode("\n", $out)]
      : ["ok" => false, "error" => implode("\n", $out)];
  }
  $out = [];
  $rc = 0;
  @exec("kill -" . $sig . " " . $pid . " 2>&1", $out, $rc);
  return $rc === 0
    ? ["ok" => true, "message" => implode("\n", $out)]
    : ["ok" => false, "error" => implode("\n", $out)];
}

// ターミナル関連関数
function default_shell(): string
{
  if (is_windows()) {
    return getenv('ComSpec') ?: 'cmd.exe';
  }
  $sh = getenv('SHELL');
  if ($sh) return $sh;
  $b = which('bash');
  if ($b) return $b;
  $s = which('sh');
  return $s ?: '/bin/sh';
}
function term_state_init(): void
{
  if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }
  if (empty($_SESSION['atk_term']) || !is_array($_SESSION['atk_term'])) {
    $_SESSION['atk_term'] = [ 'tabs' => [] ];
  }
}
function term_open(string $label = ''): array
{
  term_state_init();
  $sid = bin2hex(random_bytes(8));
  $cwd = $_SESSION['cd'] ?? (getcwd() ?: '/');
  $tab = [
    'id'    => $sid,
    'label' => ($label !== '' ? $label : ('Tab ' . (count($_SESSION['atk_term']['tabs']) + 1))),
    'cwd'   => $cwd,
    'log'   => [
      ['ts'=>time(),'type'=>'system','out'=>"Opened at ".date('c')." (cwd={$cwd})"]
    ],
  ];
  $_SESSION['atk_term']['tabs'][$sid] = $tab;
  return ['ok'=>true, 'sid'=>$sid, 'tab'=>$tab];
}
function term_list(): array
{
  term_state_init();
  $tabs = [];
  foreach ($_SESSION['atk_term']['tabs'] as $t) {
    $tabs[] = ['id'=>$t['id'], 'label'=>$t['label'], 'cwd'=>$t['cwd']];
  }
  return ['ok'=>true, 'tabs'=>$tabs];
}
function term_history(string $sid): array
{
  term_state_init();
  $t = $_SESSION['atk_term']['tabs'][$sid] ?? null;
  if (!$t) return ['ok'=>false, 'error'=>'notfound'];
  return ['ok'=>true, 'tab'=>$t];
}
function term_delete(string $sid): array
{
  term_state_init();
  if (isset($_SESSION['atk_term']['tabs'][$sid])) {
    unset($_SESSION['atk_term']['tabs'][$sid]);
    return ['ok'=>true];
  }
  return ['ok'=>false, 'error'=>'notfound'];
}

function term2_ensure_session(){
  if (session_status() !== PHP_SESSION_ACTIVE) @session_start();
  if (empty($_SESSION['atk_term2'])) $_SESSION['atk_term2'] = ['tabs'=>[]];
}
function term2_tmux_path(): ?string {
  $p = which('tmux');
  return $p && is_file($p) ? $p : null;
}
function term2_err($msg){ return ['ok'=>false, 'error'=>$msg]; }

function term2_list(): array {
  term2_ensure_session();

  $tmux = term2_tmux_path();
  $tabs = [];

  if ($tmux) {
    $out = [];
    $rc  = 0;
    exec_sudo($tmux . ' list-sessions -F "#{session_name}" 2>/dev/null', $out, $rc);
    if ($rc === 0 && is_array($out)) {
      foreach ($out as $nmRaw) {
        $nm = trim($nmRaw);
        if ($nm !== '' && preg_match('/^atkfm_([A-Za-z0-9]{4,64})$/', $nm, $m)) {
          $sid = $m[1];
          $tabs[$sid] = [
            'name'   => $nm,
            'label'  => $nm,
            'created'=> null,
            'hist_lines'=> 0,
          ];
        }
      }
    }
  }

  $_SESSION['atk_term2']['tabs'] = $tabs;

  $outTabs = [];
  foreach ($tabs as $sid => $t) {
    $outTabs[] = ['id' => $sid, 'label' => $t['label'] ?? $sid];
  }
  return ['ok' => true, 'tabs' => $outTabs];
}

function term2_open(int $cols, int $rows): array {
  if (!is_linux()) return term2_err('Linux以外では利用できません。');
  $tmux = term2_tmux_path();
  if (!$tmux) return term2_err('tmux が見つかりません（apt/yum で tmux を導入してください）。');

  term2_ensure_session();

  $sid  = 't'.substr(base_convert((string)time(),10,36), -6).bin2hex(random_bytes(2));
  $name = 'atkfm_'.$sid;

  $cwd   = isset($_SESSION['cd']) ? $_SESSION['cd'] : (rtrim(realpath("."), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR);
  $shell = getenv('SHELL') ?: '/bin/bash';
  $ps1   = "[\\u@\\h \\w]# ";

  $cmd    = 'sh -lc '.escapeshellarg('export TERM=xterm-256color; export PS1="'.$ps1.'"; exec '.escapeshellarg($shell).' -i -l');
  $create = $tmux.' new-session -d -s '.escapeshellarg($name).' -x '.(int)$cols.' -y '.(int)$rows.' -c '.escapeshellarg($cwd).' '.$cmd.' 2>&1';
  $out = []; $rc = 0; exec_sudo($create, $out, $rc);
  if ($rc !== 0) return term2_err('tmux new-session 失敗: '.implode("\n",$out));
  exec_sudo($tmux.' set-option  -t '.escapeshellarg($name).' status off 2>&1', $out, $rc);
  exec_sudo($tmux.' set-option  -t '.escapeshellarg($name).' window-size manual 2>&1', $out, $rc);
  exec_sudo($tmux.' resize-window -t '.escapeshellarg($name).' -x '.(int)$cols.' -y '.(int)$rows.' 2>&1', $out, $rc);

  $_SESSION['atk_term2']['tabs'][$sid] = [
    'name'=>$name,
    'label'=>$name,
    'created'=>time(),
    'hist_lines'=>0,
  ];
  return ['ok'=>true, 'sid'=>$sid];
}

function term2_validate_sid(string $sid): ?string {
  if (!preg_match('/^[A-Za-z0-9]{4,64}$/', $sid)) {
    return null;
  }
  $tmux = term2_tmux_path();
  if (!$tmux) {
    return null;
  }

  $name = 'atkfm_' . $sid;

  $out = [];
  $rc  = 0;
  exec_sudo($tmux . ' has-session -t ' . escapeshellarg($name) . ' 2>/dev/null', $out, $rc);
  if ($rc !== 0) {
    return null;
  }
  return $name;
}

function term2_read(string $sid): array {
  if (!is_linux()) return term2_err('Linux以外では利用できません。');
  $tmux = term2_tmux_path();
  if (!$tmux) return term2_err('tmux が見つかりません。');
  $name = term2_validate_sid($sid);
  if (!$name) return term2_err('invalid sid');

  $fmt = '#{pane_height} #{pane_width} #{cursor_y} #{cursor_x}';
  $o = []; $rc = 0;
  exec_sudo($tmux.' display-message -p -t '.escapeshellarg($name).' "'.$fmt.'" 2>/dev/null', $o, $rc);
  $h=$w=$cy=$cx = 0;
  if ($rc===0 && !empty($o)) {
    $parts = preg_split('/\s+/', trim($o[0]));
    $h = max(1, (int)($parts[0] ?? 0));
    $w = max(1, (int)($parts[1] ?? 0));
    $cy = max(0, (int)($parts[2] ?? 0));
    $cx = max(0, (int)($parts[3] ?? 0));
  } else {
    $h = 24; $w = 80; $cy = 0; $cx = 0;
  }

  $lines = []; $rc = 0;
  $cap = $tmux.' capture-pane -p -e -J -t '.escapeshellarg($name).' -S - -E -';
  exec_sudo($cap.' 2>/dev/null', $lines, $rc);
  if ($rc !== 0 || !is_array($lines)) $lines = [];

  if (count($lines) > $h) {
    $lines = array_slice($lines, -$h);
  } else {
    $pad = $h - count($lines);
    if ($pad > 0) $lines = array_merge(array_fill(0, $pad, ''), $lines);
  }

  $txt = implode("\n", $lines);
  if ($txt !== '') {
    $txt = str_replace("\x0c", "", $txt);
  }

  return [
    'ok'      => true,
    'out_b64' => base64_encode($txt),
    'cx'      => $cx,
    'cy'      => $cy,
    'w'       => $w,
    'h'       => $h,
  ];
}

function term2_write(string $sid, string $b64): array {
  if (!is_linux()) return term2_err('Linux以外では利用できません。');
  $tmux = term2_tmux_path();
  if (!$tmux) return term2_err('tmux が見つかりません。');
  $name = term2_validate_sid($sid);
  if (!$name) return term2_err('invalid sid');

  $data = base64_decode($b64, true);
  if ($data===false) return term2_err('bad base64');

  $tmp = tempnam(sys_get_temp_dir(), 'atkfm_term_');
  file_put_contents($tmp, $data);
  $buf = 'atkfm_buf_'.$sid.'_'.bin2hex(random_bytes(2));
  $out=[]; $rc=0;
  exec_sudo($tmux.' load-buffer -b '.escapeshellarg($buf).' '.escapeshellarg($tmp).' 2>&1', $out, $rc);
  if ($rc===0) exec_sudo($tmux.' paste-buffer -t '.escapeshellarg($name).' -b '.escapeshellarg($buf).' 2>&1', $out, $rc);
  exec_sudo($tmux.' delete-buffer -b '.escapeshellarg($buf).' 2>&1', $out, $rc);
  @unlink($tmp);
  if ($rc!==0) return term2_err('write failed');
  return ['ok'=>true];
}

function term2_resize(string $sid, int $cols, int $rows): array {
  if (!is_linux()) return term2_err('Linux以外では利用できません。');
  $tmux = term2_tmux_path();
  if (!$tmux) return term2_err('tmux が見つかりません。');
  $name = term2_validate_sid($sid);
  if (!$name) return term2_err('invalid sid');

  $out=[]; $rc=0;
  exec_sudo($tmux.' resize-window -t '.escapeshellarg($name).' -x '.(int)$cols.' -y '.(int)$rows.' 2>&1', $out, $rc);
  return $rc===0 ? ['ok'=>true] : term2_err('resize failed: '.implode("\n",$out));
}

function term2_close(string $sid): array {
  if (!is_linux()) return term2_err('Linux以外では利用できません。');
  $tmux = term2_tmux_path();
  if (!$tmux) return term2_err('tmux が見つかりません。');
  $name = term2_validate_sid($sid);
  if (!$name) return term2_err('invalid sid');

  $out=[]; $rc=0; exec_sudo($tmux.' kill-session -t '.escapeshellarg($name).' 2>&1', $out, $rc);
  term2_ensure_session();
  unset($_SESSION['atk_term2']['tabs'][$sid]);
  return ['ok'=> $rc===0];
}

function sanitize_interactive_fallback(string $cmd): string
{
  $trim = ltrim($cmd);
  if (preg_match('/^top(\s|$)/', $trim) && !preg_match('/\s-b(\s|$)/', $trim)) {
    if (!preg_match('/\s-n\s+\d+/', $trim)) {
      $cmd .= ' -b -n 1';
    } else {
      $cmd .= ' -b';
    }
  }
  if (preg_match('/^\s*(less|more|vi|vim|nano|htop|watch|man|ssh)(\s|$)/', $trim)) {
    $cmd = 'printf "This command is interactive and not supported in fallback mode.\n"';
  }
  return $cmd;
}

function term_run(string $sid, string $input, int $cols = 120, int $rows = 30): array
{
  term_state_init();
  if (!isset($_SESSION['atk_term']['tabs'][$sid])) {
    return ['ok'=>false, 'error'=>'notfound'];
  }

  $t = $_SESSION['atk_term']['tabs'][$sid];
  $cwd = $t['cwd'];
  $cmd = trim($input);
  if ($cmd === '') {
    return ['ok'=>true, 'out'=>'', 'cwd'=>$cwd];
  }
  if (session_status() === PHP_SESSION_ACTIVE) {
    @session_write_close();
  }

  $env = ['TERM' => 'dumb'];
  if (!is_windows()) {
    $cmd = sanitize_interactive_fallback($cmd);
  }

  $wrapped = is_windows()
    ? ('cd /d ' . escapeshellarg($cwd) . ' & ' . $cmd . ' & echo __PWD__=%cd%')
    : ('cd ' . escapeshellarg($cwd) . '; ' . $cmd . '; printf "\n__PWD__=%s\n" "$PWD"');

  $des = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];

  if (is_windows()) {
    $cm = getenv('ComSpec') ?: 'cmd.exe';
    $proc = @proc_open($cm.' /C '.$wrapped, $des, $pipes, $cwd);
  } else {
    $shell = default_shell();
    $cmdline = $shell.' -lc '.escapeshellarg($wrapped);
    // RUN_AS_ROOT なら sudo で昇格
    $proc  = proc_open_sudo_linux($cmdline, $des, $pipes, $cwd, $env);
  }

  if (!is_resource($proc)) {
    return ['ok'=>false, 'error'=>'spawn failed'];
  }

  fclose($pipes[0]);
  stream_set_blocking($pipes[1], false);
  stream_set_blocking($pipes[2], false);

  $status = @proc_get_status($proc);
  $pid = (int)($status['pid'] ?? 0);
  if ($pid > 0) term_record_pid($sid, $pid);

  $buf = '';
  while (true) {
    $status = @proc_get_status($proc);
    $running = $status && !empty($status['running']);

    $r1 = @fread($pipes[1], 65536);
    $r2 = @fread($pipes[2], 65536);
    if ($r1 !== false && $r1 !== '') $buf .= $r1;
    if ($r2 !== false && $r2 !== '') $buf .= $r2;

    if (!$running) break;
    usleep(100000);
  }

  if (is_resource($pipes[1])) fclose($pipes[1]);
  if (is_resource($pipes[2])) fclose($pipes[2]);
  @proc_close($proc);
  term_clear_pid($sid);

  $newCwd = $cwd;
  if (preg_match('/^__PWD__\s*=\s*(.+)\s*$/m', $buf, $m)) {
    $newCwd = rtrim($m[1]);
    $buf = preg_replace('/^__PWD__\s*=\s*.+\s*$/m', '', $buf);
  }

  @session_start();
  term_state_init();
  if (isset($_SESSION['atk_term']['tabs'][$sid])) {
    $_SESSION['atk_term']['tabs'][$sid]['cwd'] = $newCwd;
    $_SESSION['atk_term']['tabs'][$sid]['log'][] = ['ts'=>time(),'type'=>'in','cmd'=>$cmd];
    $_SESSION['atk_term']['tabs'][$sid]['log'][] = ['ts'=>time(),'type'=>'out','out'=>$buf];
  }

  return ['ok'=>true, 'out'=>$buf, 'cwd'=>$newCwd];
}

function term_fallback_pid_path(string $sid): string
{
  if (session_status() !== PHP_SESSION_ACTIVE) @session_start();
  $sess = session_id() ?: 'nosess';
  return sys_get_temp_dir() . DIRECTORY_SEPARATOR . "atkfm_termfb_{$sess}_{$sid}.json";
}
function term_record_pid(string $sid, int $pid): void
{
  $p = term_fallback_pid_path($sid);
  @file_put_contents($p, json_encode(['pid'=>$pid, 'ts'=>time()]));
}
function term_get_pid(string $sid): ?int
{
  $p = term_fallback_pid_path($sid);
  $j = @file_get_contents($p);
  if ($j === false) return null;
  $d = json_decode($j, true);
  $pid = (int)($d['pid'] ?? 0);
  return $pid > 0 ? $pid : null;
}
function term_clear_pid(string $sid): void
{
  @unlink(term_fallback_pid_path($sid));
}

function posix_kill_tree_int(int $pid, int $sig = 2): bool
{
  $killed = false;

  if (!is_dir('/proc')) {
    if (function_exists('posix_kill')) {
      $killed = @posix_kill($pid, $sig);
    } else {
      $rc = 0; $out = [];
      @exec('kill -' . intval($sig) . ' ' . intval($pid) . ' 2>/dev/null', $out, $rc);
      $killed = ($rc === 0);
    }
    return $killed;
  }

  $pp = [];
  foreach (glob('/proc/[0-9]*/stat') as $statf) {
    $s = @file_get_contents($statf);
    if ($s === false) continue;
    $parts = explode(')', $s, 2);
    if (count($parts) < 2) continue;
    $after = trim($parts[1]);
    $fields = preg_split('/\s+/', $after);
    if (count($fields) < 2) continue;
    $ppid = (int)$fields[1];
    $cpid = (int)basename(dirname($statf));
    $pp[$ppid][] = $cpid;
  }

  $stack = [$pid];
  $all = [];
  while ($stack) {
    $p = array_pop($stack);
    if (isset($all[$p])) continue;
    $all[$p] = true;
    foreach ($pp[$p] ?? [] as $ch) $stack[] = $ch;
  }

  foreach (array_keys($all) as $p) {
    if (function_exists('posix_kill')) {
      @posix_kill($p, $sig);
    } else {
      $rc = 0; $out = [];
      @exec('kill -' . intval($sig) . ' ' . intval($p) . ' 2>/dev/null', $out, $rc);
    }
    $killed = true;
  }
  return $killed;
}

function win_kill_tree_force(int $pid): bool
{
  $out = []; $rc = 0;
  @exec('taskkill /PID ' . intval($pid) . ' /T', $out, $rc);
  return ($rc === 0);
}

function term_interrupt(string $sid): array
{
  $pid = term_get_pid($sid);
  if (!$pid) return ['ok'=>false, 'error'=>'no running process'];
  $ok = is_windows()
    ? win_kill_tree_force($pid)
    : posix_kill_tree_int($pid, 2); // SIGINT
  return $ok ? ['ok'=>true] : ['ok'=>false, 'error'=>'signal failed'];
}

// ATK-FM用の内部関数
function remove_directory($dir)
{
  if (!is_dir($dir)) {
    return false;
  }
  $items = array_diff(scandir($dir), [".", ".."]);
  foreach ($items as $f) {
    $p = $dir . DIRECTORY_SEPARATOR . $f;
    if (is_dir($p)) {
      remove_directory($p);
    } else {
      @unlink($p);
    }
  }
  return @rmdir($dir);
}
function zipDirectory($dir, $file, $root = "")
{
  $zip = new ZipArchive();
  $res = $zip->open($file, ZipArchive::CREATE | ZipArchive::OVERWRITE);
  if ($res !== true) {
    return false;
  }
  $rootPrefix = $root
    ? rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR
    : "";
  $iter = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(
      $dir,
      FilesystemIterator::SKIP_DOTS |
        FilesystemIterator::KEY_AS_PATHNAME |
        FilesystemIterator::CURRENT_AS_FILEINFO
    ),
    RecursiveIteratorIterator::SELF_FIRST
  );
  foreach ($iter as $path => $info) {
    $local =
      $rootPrefix . ltrim(str_replace($dir, "", $path), DIRECTORY_SEPARATOR);
    if ($info->isDir()) {
      $zip->addEmptyDir($local);
    } else {
      $zip->addFile($path, $local);
    }
  }
  $zip->close();
  return true;
}
function is_utf8($str)
{
  return (bool) preg_match("//u", $str);
}
function dir_size($dir)
{
  $size = 0;
  if (!is_dir($dir)) {
    return 0;
  }
  $it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
  );
  foreach ($it as $f) {
    if ($f->isFile()) {
      $size += $f->getSize();
    }
  }
  return $size;
}
function used_bytes($dir)
{
  $size = dir_size($dir);
  $u = ["B", "KB", "MB", "GB", "TB", "EB", "ZB", "YB"];
  $base = 1024;
  $cls = $size > 0 ? min((int) floor(log($size, $base)), count($u) - 1) : 0;
  return sprintf("%1.2f", $size / pow($base, $cls)) . $u[$cls];
}
function calcFileSize($size)
{
  if (!is_numeric($size) || $size < 0) {
    return "0.00KB";
  }
  $b = 1024;
  $mb = pow($b, 2);
  $gb = pow($b, 3);
  if ($size >= $gb) {
    $unit = "GB";
    $target = $gb;
  } elseif ($size >= $mb) {
    $unit = "MB";
    $target = $mb;
  } else {
    $unit = "KB";
    $target = $b;
  }
  $new = round($size / $target, 2);
  return number_format($new, 2, ".", ",") . $unit;
}
function dir_copy($src, $dst)
{
  if (!is_dir($src)) {
    return @copy($src, $dst);
  }
  @mkdir($dst, 0755, true);
  $it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
  );
  foreach ($it as $p => $info) {
    $rel = substr($p, strlen($src) + 1);
    $to = $dst . DIRECTORY_SEPARATOR . $rel;
    if ($info->isDir()) {
      @mkdir($to, 0755, true);
    } else {
      @copy($p, $to);
    }
  }
  return true;
}
function download($weburl, $filepath)
{
  $fp = @fopen($filepath, "w+");
  if (!$fp) {
    return;
  }
  $ch = curl_init($weburl);
  curl_setopt($ch, CURLOPT_FILE, $fp);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
  curl_setopt($ch, CURLOPT_TIMEOUT, 300);
  curl_setopt($ch, CURLOPT_USERAGENT, "ATK-FM Fetch (PHP)");
  curl_exec($ch);
  curl_close($ch);
  fclose($fp);
}
function zip_list_virtual(string $zipPath): ?array
{
  $zip = new ZipArchive();
  if ($zip->open($zipPath) !== true) {
    return null;
  }
  $out = [];
  for ($i = 0; $i < $zip->numFiles; $i++) {
    $stat = $zip->statIndex($i);
    if (!$stat) {
      continue;
    }
    $name = $stat["name"];
    if ($name === "" || $name === "/") {
      continue;
    }
    $out[] = $name;
  }
  $zip->close();
  sort($out);
  return $out;
}
function zip_read_file(string $zipPath, string $fileInside): ?string
{
  $zip = new ZipArchive();
  if ($zip->open($zipPath) !== true) {
    return null;
  }
  $stream = $zip->getFromName($fileInside);
  $zip->close();
  return $stream === false ? null : $stream;
}
function hex_dump_html(string $file)
{
  $data = @file_get_contents($file);
  if ($data === false) {
    echo "エラー: 読み込み失敗";
    return;
  }
  $hex = bin2hex($data);
  echo "<h1>HexDump - ATK-FM</h1><pre>File: " .
    htmlspecialchars($file) .
    "</pre><pre>";
  $len = strlen($hex);
  for ($i = 0; $i < $len; $i += 2) {
    if ($i > 0 && ($i / 2) % 20 === 0) {
      echo "\n";
    }
    echo substr($hex, $i, 2) . " ";
  }
  echo "</pre>";
}

function ViewNotePad($filepath)
{
  $title = basename($filepath);
  $ext = strtolower(pathinfo($filepath, PATHINFO_EXTENSION));

  // 簡易ビュワーで表示
  if (in_array($ext, ["bmp", "png", "jpeg", "ico", "gif", "jpg"], true)) {
    $data = base64_encode((string) file_get_contents($filepath));
    $type = $ext === "jpeg" ? "jpg" : $ext;
    echo '<div align="center"><img style="max-width:100%" src="data:image/' .
      $type .
      ";base64," .
      $data .
      '"></div>';
    exit();
  }
  if (in_array($ext, ["mp3", "m4a", "ogg"], true)) {
    header("Content-Type: audio/mpeg");
    header("Content-Length: " . filesize($filepath));
    readfile($filepath);
    exit();
  }
  if ($ext === "pdf") {
    $data = base64_encode((string) file_get_contents($filepath));
    echo '<body style="height:100%;margin:0;background:#0b0b0b"><embed width="100%" height="100%" type="application/pdf" src="data:application/pdf;base64,' .
      $data .
      '"></body>';
    exit();
  }
  if ($ext === "mp4") {
    header("Content-Type: video/mp4");
    header("Content-Length: " . filesize($filepath));
    readfile($filepath);
    exit();
  }
  if (in_array($ext, ["zip", "7z"], true)) {
    header("Content-Type: application/zip");
    header("Content-Length: " . filesize($filepath));
    readfile($filepath);
    exit();
  }

  // テキストファイルの場合はエディタで開く
  $raw = @file_get_contents($filepath);
  if ($raw === false && app_run_as_root_enabled()) {
    $raw = root_fs_read($filepath);
  }
  if ($raw === false) {
    $raw = "// ファイルが見つかりませんでした。";
  }
  $content = is_utf8($raw)
    ? $raw
    : @mb_convert_encoding($raw, "UTF-8", "SJIS,UTF-8,EUC-JP,ISO-2022-JP");

  $isReadonly = isset($_GET["readonly"]);
  $lang = "markdown";
  if ($ext === "rs") {
    $lang = "rust";
  } elseif ($ext === "php") {
    $lang = "php";
  } elseif ($ext === "js") {
    $lang = "javascript";
  } elseif ($ext === "css") {
    $lang = "css";
  } elseif ($ext === "html" || $ext === "htm") {
    $lang = "html";
  } elseif ($ext === "json") {
    $lang = "json";
  } elseif ($ext === "ts") {
    $lang = "typescript";
  } elseif ($ext === "py") {
    $lang = "python";
  } elseif ($ext === "c") {
    $lang = "c";
  } elseif (in_array($ext, ["cpp", "cc", "cxx", "hpp", "h"], true)) {
    $lang = "cpp";
  } elseif ($ext === "go") {
    $lang = "go";
  } elseif (in_array($ext, ["sh", "bash"], true)) {
    $lang = "shell";
  }
  ?>
<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title><?= htmlspecialchars($title) ?> - Web File Editor</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://project.activetk.jp/MarkDown/node_modules/monaco-editor/min/vs/loader.js"></script>
  <style>
    :root { color-scheme: dark; }
    body { background:#080808; color:#e5e7eb; margin:0; }
    a.atkfm-underline{color:#0f0;position:relative;display:inline-block;transition:.3s}
    a.atkfm-underline:after{position:absolute;bottom:0;left:50%;content:'';width:0;height:2px;background-color:#31aae2;transform:translateX(-50%);transition:.3s}
    a.atkfm-underline:hover:after{width:100%}

    .bar { position:sticky; top:0; z-index:10; background:#0b0b0b; border-bottom:1px solid #1f2937; }
    .bar-wrap { max-width: 1500px; margin: 0 auto; padding: 8px 12px; display:flex; gap:8px; align-items:center; }
    .path { flex:1 1 auto; min-width:0; }
    .path input { width:100%; background:#0a0f1a; color:#e5e7eb; border:1px solid #334155; border-radius:8px; padding:8px 10px; font-size:12px; }
    .btn { display:inline-flex; align-items:center; justify-content:center; padding:10px 14px; border-radius:10px; border:1px solid #334155; background:#0f172a; color:#e5e7eb; font-size:14px; }
    .btn:hover{ background:#111827; }
    .btn.primary{ background:#075985; border-color:#075985; }
    .btn.primary:hover{ background:#0369a1; }
    .wrap { max-width: 1500px; margin: 0 auto; padding: 12px; }
    #editor { height: calc(100vh - 160px); border:1px solid #1f2937; border-radius:10px; overflow:hidden; }

    .informationbar { position: fixed; bottom: 0; left: 0; right: 0; height: 24px; width: 100vw; }
    .rightside { position: fixed; right: 20px; bottom: 0; }
    .littleleftmargin { margin-left: 5px; }
    .copyright { color: #00ff33; }
  </style>
</head>
<body>
  <header class="bar">
    <div class="bar-wrap">
      <div class="text-sm text-slate-300">Web File Editor</div>
      <div class="path">
        <input type="text" id="pt" value="<?= htmlspecialchars(
          $filepath
        ) ?>" readonly>
      </div>
      <?php if (!$isReadonly): ?>
        <button id="btnSave" class="btn primary">保存 (Ctrl+S)</button>
      <?php endif; ?>
      <button id="btnDownload" class="btn">ダウンロード</button>
      <button id="btnClear" class="btn">クリア</button>
    </div>
  </header>

  <main class="wrap">
    <div id="editor"></div>
  </main>

  <div class="informationbar bg-blue-600 text-white">
    <span class="littleleftmargin">Web File Editor&gt; <span id="message2print"></span>
    <span class="rightside">
      <span class="copyright littleleftmargin">(c) 2025 ActiveTK.</span>
    </span>
  </div>

<script>
  const FILEPATH = <?= json_encode(
    $filepath,
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
  ) ?>;
  const IS_READONLY = <?= $isReadonly ? "true" : "false" ?>;
  const INITIAL = <?= json_encode($content, JSON_UNESCAPED_UNICODE) ?>;
  const LANG = <?= json_encode($lang) ?>;

  let lastSavedValue = INITIAL;
  let isDirty = false;

  const setMsg = (t)=>{
    const el = document.getElementById('message2print');
    if (el) el.textContent = t || '';
  };

  function bindBeforeUnload(){
    if (IS_READONLY) return;
    window.onbeforeunload = (e)=>{
      if (isDirty) { e.preventDefault(); e.returnValue = ''; return ''; }
      return undefined;
    };
  }
  function clearBeforeUnload(){
    window.onbeforeunload = null;
  }

  require.config({ paths: { vs: "https://project.activetk.jp/MarkDown/node_modules/monaco-editor/min/vs" }});
  require(["vs/editor/editor.main"], function () {
    window.monacoeditor = monaco.editor.create(document.getElementById("editor"), {
      value: INITIAL,
      language: LANG,
      theme: "vs-dark",
      readOnly: IS_READONLY,
      automaticLayout: true,
      fontSize: 14, // 字が小さくて読めない！って人は大きくしてね。デフォ14にしてある。
      minimap: { enabled: true }
    });

    setMsg('準備完了');

    const updateStats = ()=>{
      const s = window.monacoeditor.getValue();
      setMsg(`${s.length}文字 / ${s.split("\n").length}行${(IS_READONLY?'':'')}`);
      isDirty = (!IS_READONLY && s !== lastSavedValue);
      document.title = (isDirty ? '* ' : '') + <?= json_encode(
        $title
      ) ?> + ' - Web File Editor';
    };
    updateStats();
    window.monacoeditor.onDidChangeModelContent(updateStats);

    async function save(){
      try{
        const body = new FormData();
        body.append('naka', window.monacoeditor.getValue());
        const res = await fetch(`?ajax-typeof=save-item&ajax-option=${encodeURIComponent(FILEPATH)}`, { method:'POST', body });
        const t = await res.text();
        if (t==='') {
          lastSavedValue = window.monacoeditor.getValue();
          isDirty = false;
          setMsg('変更を保存しました。');
        } else {
          setMsg('変更を保存できませんでした。');
        }
      } catch(e){
        setMsg('エラー: 変更を保存できませんでした。');
      }
    }

    function download(){
      const blob = new Blob([window.monacoeditor.getValue()], {type:'text/plain;charset=utf-8'});
      const a = document.createElement('a');
      const stamp = new Date();
      const fn = <?= json_encode($title) ?> + '_' +
                 stamp.getFullYear() + String(stamp.getMonth()+1).padStart(2,'0') +
                 String(stamp.getDate()).padStart(2,'0') + '-' +
                 String(stamp.getHours()).padStart(2,'0') + String(stamp.getMinutes()).padStart(2,'0') +
                 String(stamp.getSeconds()).padStart(2,'0');
      a.href = URL.createObjectURL(blob);
      a.download = fn;
      a.click();
      URL.revokeObjectURL(a.href);
      setMsg('ダウンロードを開始しました。');
    }

    function clearDoc(){
      window.monacoeditor.setValue('');
    }

    const btnSave = document.getElementById('btnSave');
    if (btnSave) btnSave.addEventListener('click', save);
    document.getElementById('btnDownload').addEventListener('click', download);
    document.getElementById('btnClear').addEventListener('click', clearDoc);

    document.addEventListener('keydown', (e)=>{
      if (e.ctrlKey && (e.key==='s' || e.key==='S')) {
        if (!IS_READONLY) save();
        e.preventDefault();
      }
    });

    // 未保存の場合の警告
    bindBeforeUnload();
  });
</script>
</body>
</html>
<?php exit();
}

function ViewListPreview(string $dir)
{
  header("Content-Type: text/html; charset=utf-8");
  if (!is_dir($dir)) {
    echo "ディレクトリが存在しません";
    return;
  }
  $list = glob(rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . "*");
  ?>
<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title><?= htmlspecialchars(
  $dir
) ?> | プレビュー一覧</title></head>
<body style="background:#6495ed;color:#080808;">
  <div align="center">
    <h1>ファイルのプレビュー一覧 / ATK-FM</h1>
    <pre><?= htmlspecialchars($dir) ?></pre>
    <hr>
    <?php
    $i = 0;
    foreach ($list as $p) {
      if (!is_file($p)) {
        continue;
      }
      $i++;
      $ext = strtolower(pathinfo($p, PATHINFO_EXTENSION) ?: "");
      echo "<pre>";
      echo "統計ファイル番号: {$i}\n";
      echo "ファイル名: " . htmlspecialchars(basename($p)) . "\n";
      echo "サイズ: " .
        calcFileSize(filesize($p)) .
        " (" .
        filesize($p) .
        "B)\n";
      echo "md5: " . @md5_file($p) . "\n";
      echo "</pre>";
      if ($i > 500) {
        echo "(500件以降は省略。<a href=\"?ajax-typeof=download-item&ajax-option=" .
          urlencode($p) .
          "\" target=\"_blank\">ダウンロード</a>)";
        continue;
      }
      if (filesize($p) > 10 * 1024 * 1024) {
        echo "(10MB超は非表示。<a href=\"?ajax-typeof=get-item&ajax-option=" .
          urlencode($p) .
          "\" target=\"_blank\">プレビュー</a>)";
        continue;
      }
      if (in_array($ext, ["png", "jpg", "jpeg", "gif", "bmp"])) {
        echo "<img style='height:340px' src='?ajax-typeof=get-item&ajax-option=" .
          urlencode($p) .
          "&accept=image/{$ext}'>";
      } elseif (
        in_array($ext, [
          "txt",
          "readme",
          "md",
          "js",
          "css",
          "php",
          "json",
          "c",
          "cs",
          "py",
          "go",
          "vbs",
        ])
      ) {
        echo "<iframe style='width:604px;height:340px' src='?ajax-typeof=get-item-pre&ajax-option=" .
          urlencode($p) .
          "'></iframe>";
      } elseif (in_array($ext, ["html", "shtml", "htm"])) {
        echo "<iframe style='width:604px;height:340px' sandbox src='?ajax-typeof=get-item&ajax-option=" .
          urlencode($p) .
          "&accept=text/html'></iframe>";
      } elseif ($ext === "pdf") {
        echo "<iframe style='width:604px;height:340px' src='?ajax-typeof=get-item&ajax-option=" .
          urlencode($p) .
          "&accept=application/pdf'></iframe>";
      } elseif ($ext === "mp3") {
        echo "<audio controls src='?ajax-typeof=get-item&ajax-option=" .
          urlencode($p) .
          "&accept=audio/mp3'></audio>";
      } elseif ($ext === "mp4") {
        echo "<iframe style='height:340px' src='?ajax-typeof=get-item&ajax-option=" .
          urlencode($p) .
          "&accept=video/mp4'></iframe>";
      } else {
        echo "(プレビュー不可。<a href='?ajax-typeof=download-item&ajax-option=" .
          urlencode($p) .
          "' target='_blank'>ダウンロード</a>)";
      }
      echo "<hr>";
    }
    ?>
  </div>
</body></html>
<?php exit();
}

$STATIC_INFO = static_info();
$IS_WINDOWS = is_windows();
?>
<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>WebTaskmgr / ATK-FM v2.0.1</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css">
<script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
<style>
  canvas { width: 100%; height: 160px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
  .table-fixed th { cursor: pointer; }

  .atkfm-link,
  .atkfm-underline {
    color:#0f0; position:relative; display:inline-block; transition:.3s;
  }
  .atkfm-link::after,
  .atkfm-underline::after {
    position:absolute; bottom:0; left:50%; content:''; width:0; height:2px; background-color:#31aae2;
    transform:translateX(-50%); transition:.3s;
  }
  .atkfm-link:hover::after,
  .atkfm-underline:hover::after { width:100%; }

  .atkfm-wrap { height: calc(100vh - 140px); }
  @media (max-width:1024px){ .atkfm-wrap { height: calc(100vh - 180px); } }

  .atkfm-panel { display:flex; flex-direction:column; height:100%; }
  .atkfm-panel-head {
    position: sticky; top: 0;
    background: rgba(2,6,23,0.85);
    backdrop-filter: blur(6px);
    border-bottom: 1px solid #1f2937;
    padding: 10px;
    z-index: 1;
  }
  .atkfm-panel-body { flex:1 1 auto; overflow:auto; padding: 12px; }

  .atkfm-input {
    background-color:#0b1220;
    color:#e5e7eb;
    border:1px solid #334155;
    border-radius:8px;
    padding:8px 10px;
    line-height:1.25;
    width:auto;
  }
  .atkfm-input::placeholder { color:#64748b; }

  .atkfm-btn {
    display:inline-flex; align-items:center; justify-content:center; gap:.5rem;
    background:#0f172a;
    color:#e5e7eb;
    border:1px solid #334155; border-radius:10px;
    padding:10px 12px; font-size:14px; line-height:1.2;
  }
  .atkfm-btn:hover { background:#111827; }
  .atkfm-btn--danger { background:#7f1d1d; border-color:#7f1d1d; }
  .atkfm-btn--danger:hover { background:#991b1b; }
  .atkfm-btn--accent { background:#075985; border-color:#075985; }
  .atkfm-btn--accent:hover { background:#0369a1; }
  .atkfm-tag {
    display:inline-block; padding:2px 8px; border-radius:9999px; font-size:12px; border:1px solid #334155; color:#cbd5e1;
  }

  .fm-notice{
    display:flex; align-items:center; gap:.5rem;
    min-height:40px; padding:8px 12px; margin-left:12px;
    border:1px solid; border-radius:10px;
    font-size:14px; line-height:1.35;
    white-space:pre-wrap; word-break:break-word;
  }
  .fm-notice .msg{ flex:1 1 auto; color:#e5e7eb; }
  .fm-notice .close{
    appearance:none; border:0; cursor:pointer;
    font-size:16px; line-height:1; padding:2px 8px; border-radius:8px;
    background:transparent; color:#cbd5e1;
  }
  .fm-notice .close:hover{ background:#1f2937; color:#fff; }

  .fm-notice.is-info  { background:#0b1220; border-color:#334155; }
  .fm-notice.is-ok    { background:#052e1a; border-color:#16a34a; }
  .fm-notice.is-error { background:#3a0a0a; border-color:#ef4444; }

    .atkfm-inline{ display:flex; align-items:center; gap:8px; }
  .atkfm-inline .atkfm-input{ flex:1 1 auto; min-width:0; }
  .atkfm-inline .atkfm-btn{ flex:0 0 auto; }

  #pageFiles { overflow: hidden; }
  .atkfm-wrap { overflow: hidden; }

  .atkfm-panel { height: 100%; }
  .atkfm-panel-body {
    overflow: auto;
    overscroll-behavior: contain;
    -webkit-overflow-scrolling: touch;
  }
  #pageFiles .atkfm-panel { min-height: 0; }
  #pageFiles .atkfm-panel-body {
    min-height: 0;
    overflow: auto;
    -webkit-overflow-scrolling: touch;
  }
</style>
</head>
<body class="bg-slate-900 text-slate-100">
  <header class="sticky top-0 z-50 bg-slate-950/70 backdrop-blur border-b border-slate-800">
    <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
      <div class="text-lg font-semibold">WebTaskmgr / ATK-FM v2.0.1</div>
      <div class="flex gap-2">
        <button id="tabOverview" class="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500">全体概要</button>
        <button id="tabProcs"    class="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600">タスク管理</button>
        <button id="tabFiles"    class="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600">ファイル管理</button>
        <button id="tabTerminal" class="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600">ターミナル</button>
        <button id="tabSettings" class="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600">設定</button>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-4 py-4">

    <section id="pageOverview" class="space-y-4">
      <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
        <div class="text-sm text-slate-300 mb-2">システム概要</div>
        <div id="sysSpec" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-x-6 gap-y-2 text-sm"></div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
          <div class="text-sm text-slate-300">CPU (合計)</div>
          <div id="cpuTotalPct" class="text-3xl font-semibold mono">--%</div>
          <div id="cpuModel" class="text-xs text-slate-400 mt-1"></div>
          <div class="mt-2"><canvas id="cpuChart"></canvas></div>
        </div>
        <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
          <div class="text-sm text-slate-300">メモリ</div>
          <div id="memText" class="text-3xl font-semibold mono">-- / --</div>
          <div class="w-full h-2 bg-slate-700 rounded mt-2">
            <div id="memBar" class="h-2 bg-emerald-500 rounded" style="width:0%"></div>
          </div>
          <div class="mt-2"><canvas id="memChart"></canvas></div>
        </div>
        <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
          <div class="text-sm text-slate-300">Load Average</div>
          <div id="loadText" class="text-3xl font-semibold mono">-- / -- / --</div>
          <div class="mt-2"><canvas id="loadChart"></canvas></div>
        </div>
        <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
          <div class="text-sm text-slate-300">GPU</div>
          <div id="gpuSummary" class="text-base mono">検出なし</div>
          <div id="gpuCharts" class="mt-2 space-y-3"></div>
        </div>
      </div>

      <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
        <div class="text-sm text-slate-300 mb-2">CPU コア別</div>
        <div id="coresGrid" class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3"></div>
      </div>

      <div class="text-xs text-slate-500" id="platformText"></div>
    </section>

    <section id="pageProcs" class="space-y-3 hidden">
      <div class="flex items-center gap-2">
        <div class="text-sm text-slate-300">ソート:</div>
        <div id="sortLabel" class="text-sm mono">PID ▲</div>
        <div class="ml-auto text-xs text-slate-400" id="procCount"></div>
      </div>
      <div class="overflow-x-auto rounded border border-slate-800 bg-slate-800/40">
        <table class="min-w-full table-fixed">
          <thead class="bg-slate-800">
            <tr class="text-left text-xs uppercase text-slate-300">
              <th class="p-2 w-20" data-key="pid">PID</th>
              <th class="p-2 w-64" data-key="title">タイトル</th>
              <th class="p-2 w-40" data-key="user">ユーザー</th>
              <th class="p-2 w-24" data-key="cpu_percent">CPU%</th>
              <th class="p-2 w-24" data-key="mem_percent">MEM%</th>
              <th class="p-2 w-28" data-key="rss_kb">RSS(MB)</th>
              <th class="p-2 w-24" data-key="state">状態</th>
              <th class="p-2 w-20" data-key="nice">NI</th>
              <th class="p-2 w-20" data-key="priority">PRI</th>
              <th class="p-2 w-28" data-key="elapsed">経過</th>
              <th class="p-2 w-64">操作</th>
            </tr>
          </thead>
          <tbody id="procBody" class="divide-y divide-slate-800 text-sm"></tbody>
        </table>
      </div>
    </section>

    <section id="pageFiles" class="hidden">
      <div class="mb-3 p-2 rounded border border-slate-800 bg-slate-800/40">
        <span class="text-sm text-slate-300">ATK-FM</span>
        <span id="fmInfo" class="ml-3 text-base font-medium text-slate-100 tracking-wide"></span>
      </div>

      <div class="atkfm-wrap grid grid-cols-1 lg:grid-cols-2 gap-4">

        <div class="rounded border border-slate-800 bg-slate-800/40 atkfm-panel">
          <div class="atkfm-panel-head">
            <div class="flex items-center justify-between">
              <div class="text-sm text-slate-300">クライアント操作</div>
              <span class="atkfm-tag">新規/アップロード/リンク</span>
            </div>
          </div>
          <div class="atkfm-panel-body">
            <form onsubmit="fm.addFile(); return false;" class="space-y-2 mb-3">
              <label class="block text-xs text-slate-400 mb-1">ファイル名</label>
              <div class="flex flex-wrap gap-2">
                <input type="text" id="fm-add-file" value="example.txt" class="atkfm-input" />
                <button type="button" onclick="fm.addFile()" class="atkfm-btn">新規作成</button>
              </div>
            </form>

            <form onsubmit="fm.addDir(); return false;" class="space-y-2 mb-3">
              <label class="block text-xs text-slate-400 mb-1">ディレクトリ名</label>
              <div class="flex flex-wrap gap-2">
                <input type="text" id="fm-add-dir" value="example/" class="atkfm-input" />
                <button type="button" onclick="fm.addDir()" class="atkfm-btn">新規作成</button>
              </div>
            </form>

            <form id="fm-upload-form" enctype="multipart/form-data" class="space-y-2 mb-3" onsubmit="fm.upload(); return false;">
              <label class="block text-xs text-slate-400 mb-1">アップロード</label>
              <div class="flex flex-wrap gap-2 items-center">
                <input type="file" id="fm-upload-files" name="file[]" multiple class="text-sm file:mr-3 file:atkfm-btn" />
                <button type="button" onclick="fm.upload()" class="atkfm-btn atkfm-btn--accent">保存</button>
              </div>
            </form>

            <form id="fm-chunk-form" class="space-y-2 mb-3" onsubmit="fm.chunkUpload(); return false;">
             <label class="block text-xs text-slate-400 mb-1">分割アップロード</label>
              <div class="flex flex-wrap gap-2 items-center">
                <span class="text-sm">チャンク</span>
                <input type="number" id="fm-chunk-mb" value="3" class="atkfm-input" style="width:72px" />
                <span class="text-sm">MB</span>
                <input type="file" id="fm-chunk-file" class="text-sm" />
                <button type="submit" class="atkfm-btn atkfm-btn--accent">保存</button>
              </div>
            </form>

            <form onsubmit="fm.uploadFromUrl(); return false;" class="space-y-2 mb-3">
              <label class="block text-xs text-slate-400 mb-1">URLからアップロード</label>
              <div class="atkfm-inline">
                <input type="text" id="fm-url" placeholder="URLを入力してください" class="atkfm-input" />
                <button type="button" onclick="fm.uploadFromUrl()" class="atkfm-btn atkfm-btn--accent">保存</button>
              </div>
            </form>

            <form onsubmit="fm.makeLink(); return false;" class="space-y-2 mb-4">
              <label class="block text-xs text-slate-400 mb-1">このフォルダーへのショートカット</label>
              <div class="atkfm-inline">
                <input type="text" id="fm-linkto" value="" class="atkfm-input" />
                <button type="button" onclick="fm.makeLink()" class="atkfm-btn">作成</button>
              </div>
            </form>

            <hr class="my-3 border-slate-700">

            <div>
              <div class="text-xs text-slate-400">デバッグ情報</div>
              <pre id="fmDebug" class="text-xs whitespace-pre-wrap mt-1"></pre>
            </div>
          </div>
        </div>

        <div class="rounded border border-slate-800 bg-slate-800/40 atkfm-panel">
          <div class="atkfm-panel-head">
            <form onsubmit="fm.list(); return false;" class="flex flex-wrap items-center gap-2 text-sm">
              <input
                type="text"
                id="fm-root"
                value="<?= htmlspecialchars(
                  isset($_SESSION["cd"])
                    ? $_SESSION["cd"]
                    : rtrim(realpath("."), DIRECTORY_SEPARATOR) .
                      DIRECTORY_SEPARATOR
                ) ?>"
                class="atkfm-input flex-1 min-w-[220px]"
                />
              <button type="button" onclick="fm.list()" class="atkfm-btn atkfm-btn--accent">送信</button>
              <button type="button" onclick="fm.up()" class="atkfm-btn">上へ</button>
              <button type="button" onclick="fm.count()" class="atkfm-btn">詳細</button>
              <button type="button" onclick="fm.viewList()" class="atkfm-btn">閲覧</button>
            </form>
          </div>
          <div class="atkfm-panel-body">
            <div id="fm-list" class="text-sm space-y-1"></div>
          </div>
        </div>
      </div>

    <div id="fm-modal" class="hidden fixed inset-0 z-50" role="dialog" aria-modal="true" aria-labelledby="fm-modal-title">
      <div class="absolute inset-0 bg-black/60" id="fm-modal-backdrop"></div>
      <div class="relative mx-auto my-10 w-[95%] max-w-4xl rounded-lg border border-slate-800 bg-slate-950 shadow-xl">
        <div class="flex items-center justify-between border-b border-slate-800 p-4">
          <h2 id="fm-modal-title" class="text-lg font-semibold text-slate-200">操作</h2>
          <button onclick="fm.closeModal()" class="atkfm-btn" aria-label="閉じる">×</button>
        </div>
        <div class="p-4 space-y-3">
          <input id="fm-selected" type="text" class="atkfm-input w-full" readonly />
          <div id="fm-actions" class="grid grid-cols-2 sm:grid-cols-3 gap-2"></div>
        </div>
      </div>
    </div>
  </section>

<section id="pageTerminal" class="space-y-3 hidden">
  <div class="p-3 rounded border border-slate-800 bg-slate-800/40">
    <div class="flex items-center justify-between">
      <div class="text-sm text-slate-300">ターミナル</div>
      <div class="flex items-center gap-2">
        <label class="text-xs text-slate-400">Font</label>
        <select id="term-font" class="atkfm-input" style="width:84px">
          <option value="12">12px</option>
          <option value="13">13px</option>
          <option value="14" selected>14px</option>
          <option value="16">16px</option>
          <option value="18">18px</option>
          <option value="20">20px</option>
        </select>
        <button type="button" id="term-newtab" class="atkfm-btn">+ 新しいタブ</button>
      </div>
    </div>
  </div>

  <div class="rounded border border-slate-800 bg-slate-800/40 p-3">
    <div id="term-tabs" class="flex flex-wrap gap-2"></div>
    <div id="xterm-wrap" class="mt-2 rounded border border-slate-800 bg-black" style="height:60vh; overflow:hidden;">
      <div id="xterm" style="height:100%;"></div>
    </div>
  </div>
</section>

<section id="pageSettings" class="space-y-4 hidden">
  <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
    <div class="text-sm text-slate-300 mb-3">パスワード設定</div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <label class="block text-xs text-slate-400 mb-1">新しいパスワード</label>
        <input type="password" id="cfg-pass-new" class="w-full bg-slate-900/70 text-slate-100 border border-slate-700 rounded px-2 py-1">
      </div>
    </div>
    <div class="mt-3 flex gap-2">
      <button id="cfg-pass-save"  class="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500">保存</button>
      <button id="cfg-pass-clear" class="px-3 py-1.5 rounded bg-rose-600    hover:bg-rose-500">パスワード削除</button>
      <div id="cfg-pass-info" class="text-sm text-slate-300 ml-2"></div>
    </div>
  </div>

  <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
    <div class="text-sm text-slate-300 mb-3">IPアドレス制限</div>
    <div class="text-xs text-slate-400 mb-2">1行に1件(単一IPかCIDRで指定)。「#」でコメントアウトされます。</div>
    <div class="text-xs text-slate-400 mb-2">未設定だと既定で全てのIPアドレスからのアクセスを許可します。</div>
    <textarea id="cfg-ip-allow" rows="8" class="w-full bg-slate-900/70 text-slate-100 border border-slate-700 rounded px-2 py-1 mono"></textarea>
    <div class="mt-2 flex gap-2 items-center">
      <button id="cfg-ip-add-self" class="px-3 py-1.5 rounded bg-slate-600 hover:bg-slate-500">自分のIPを追加</button>
      <button id="cfg-ip-save"     class="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500">保存</button>
      <div id="cfg-ip-info" class="text-sm text-slate-300 ml-2"></div>
    </div>
    <div id="cfg-ip-me" class="text-xs text-slate-400 mt-1"></div>
    <div class="text-xs text-slate-400 mb-2">※Cloudflare等のCDN利用時にはこの設定は使用できません。</div>
  </div>

  <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
    <div class="text-sm text-slate-300 mb-3">権限設定</div>
    <div class="flex items-center gap-3">
      <input type="checkbox" id="cfg-run-root" class="w-4 h-4">
      <label for="cfg-run-root" class="text-slate-200">WebTaskmgrをroot権限で実行する</label>
    </div>
    <div id="cfg-run-root-info" class="text-sm text-slate-300 mt-2"></div>
    <div class="text-xs text-amber-300 mt-2">
      <p class="text-xs text-slate-400 mb-2">※有効化する場合には、以下をvisudoコマンドでsudoersに追加してください。</p>      <code id="cfg-sudoers-example" class="bg-slate-900 px-2 py-1 rounded border border-slate-700"></code>
    </div>
  </div>

  <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
    <div class="text-m text-slate-300 mb-3">本アプリについて (免責事項)</div>
    <div class="text-m text-slate-400 mb-2">このプログラムは、あくまでも高校生が趣味で開発しているものです。</div>
    <div class="text-m text-slate-400 mb-2">すべてオープンソースであり、MITライセンスの下で自由に編集・再配布することができますが、プログラムを利用したことによって生じた一切の責任を負いません。</div>
    <div class="text-m text-slate-400 mb-2">(c) 2025 <a href="https://profile.activetk.jp/" target="_blank">ActiveTK</a>. Released under the MIT License.</div>
  </div>

  <div class="p-4 rounded border border-slate-800 bg-slate-800/40">
    <div class="text-m text-slate-300 mb-3">クレジット</div>
    <div class="text-m text-slate-400 mb-2">Ayato様(2025年9月): CSRFの脆弱性を報告していただきました。</div>
  </div>

</section>

  </main>

<script>
const POLL_MS = 800;
const IS_WINDOWS = <?php echo $IS_WINDOWS ? "true" : "false"; ?>;
const STATIC_INFO = <?php echo json_encode( $STATIC_INFO, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES ); ?>;

const state = {
  activeTab: 'overview',
  pollTimer: null,
  lastCpu: null,
  lastCpuPrev: null,
  series: { cpuTotal: [], memPct: [], load1: [], gpu: {} },
  seriesMaxPoints: Math.max(2, Math.round(60000 / POLL_MS)),
  sortKey: 'pid',
  sortDir: 'asc',
  procs: [],
  inFlight: false,
  controller: null,
  fmInit: false
};

// CSRF
(() => {
  const orig = window.fetch;
  window.fetch = function(input, init) {
    init = init || {};
    const url = (typeof input === 'string') ? input : (input?.url || '');
    const sameOrigin = !/^https?:\/\//i.test(url) || url.startsWith(location.origin);
    const method = (init.method || 'GET').toUpperCase();

    if (sameOrigin && method !== 'GET' && method !== 'HEAD') {
      const ck = document.cookie.split('; ').find(s => s.startsWith('ATKFM_CSRF='));
      if (ck) {
        const val = decodeURIComponent(ck.split('=').slice(1).join('='));
        if (val) {
          if (init.headers instanceof Headers) {
            init.headers.set('X-CSRF-Token', val);
          } else {
            init.headers = init.headers || {};
            init.headers['X-CSRF-Token'] = val;
          }
        }
      }
    }

    return orig(input, init);
  };
})();

// 諸々の便利関数とか
const fmtPct = v => (v==null||isNaN(v)) ? '--%' : (v.toFixed(1)+'%');
const fmtMiB = kb => (kb==null) ? '--' : (kb/1024).toFixed(1)+' MiB';
const clamp = (v,a,b) => Math.max(a, Math.min(b, v));

function utf8ToBase64(str){
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function base64ToUtf8(b64){
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

function ringPush(arr, v, maxN) {
  arr.push(v);
  if (arr.length > maxN) arr.shift();
}

function drawLine(canvas, data, yMaxHint = null) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width = canvas.clientWidth * window.devicePixelRatio;
  const H = canvas.height = canvas.clientHeight * window.devicePixelRatio;
  ctx.clearRect(0, 0, W, H);

  const N = data.length;
  if (N === 0) return;

  const yMax = yMaxHint ?? Math.max(100, Math.max(...data.filter(x => isFinite(x))));
  const yMin = 0;

  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let y = 0; y <= H; y += H / 4) {
    ctx.moveTo(0, y);
    ctx.lineTo(W, y);
  }
  ctx.stroke();

  ctx.lineWidth = Math.max(1, Math.floor(H / 160));
  ctx.strokeStyle = '#60a5fa';
  ctx.beginPath();
  for (let i = 0; i < N; i++) {
    const x = (i / (Math.max(1, N - 1))) * (W - 2) + 1;
    const v = clamp(data[i], yMin, yMax);
    const y = H - ((v - yMin) / (yMax - yMin)) * (H - 2) - 1;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();
}

function bytesHum(kb) {
  if (kb == null) return '--';
  const mb = kb / 1024;
  return mb < 1024 ? mb.toFixed(1) + ' MiB' : (mb / 1024).toFixed(2) + ' GiB';
}

function computeCpuPct(prev, curr) {
  if (!prev || !curr) return null;
  const sum = a => a.reduce((x, y) => x + y, 0);
  const totald = sum(curr) - sum(prev);
  const idled = (curr[3] + (curr[4] || 0)) - (prev[3] + (prev[4] || 0));
  if (totald <= 0) return 0;
  return (1 - idled / totald) * 100;
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));
}

// タブ切り替えの処理
const tabOverview = document.getElementById('tabOverview');
const tabProcs = document.getElementById('tabProcs');
const tabFiles = document.getElementById('tabFiles');
const tabTerminal = document.getElementById('tabTerminal');
const tabSettings = document.getElementById('tabSettings');

const pageOverview = document.getElementById('pageOverview');
const pageProcs = document.getElementById('pageProcs');
const pageFiles = document.getElementById('pageFiles');
const pageTerminal = document.getElementById('pageTerminal');
const pageSettings = document.getElementById('pageSettings');

tabOverview.addEventListener('click', () => setTab('overview'));
tabProcs.addEventListener('click', () => setTab('procs'));
tabFiles.addEventListener('click', () => setTab('files'));
tabTerminal.addEventListener('click', () => setTab('terminal'));
tabSettings.addEventListener('click', () => setTab('settings'));

function abortInFlight() {
  if (state.controller) {
    try { state.controller.abort(); } catch {}
    state.controller = null;
  }
  state.inFlight = false;
}

let suppressHash = false;

function tabFromHash() {
  const h = (location.hash || '').replace(/^#/, '');
  return (h === 'files' || h === 'procs' || h === 'overview' || h === 'settings' || h === 'terminal') ? h : 'overview';
}

function setTab(t) {
  state.activeTab = t;

  for (const [btn, on] of [
    [tabOverview, t === 'overview'],
    [tabProcs,    t === 'procs'],
    [tabFiles,    t === 'files'],
    [tabTerminal, t === 'terminal'],
    [tabSettings, t === 'settings']
  ]) {
    btn.classList.toggle('bg-blue-600', on);
    btn.classList.toggle('bg-slate-700', !on);
  }

  pageOverview.classList.toggle('hidden', t !== 'overview');
  pageProcs.classList.toggle('hidden',    t !== 'procs');
  pageFiles.classList.toggle('hidden',    t !== 'files');
  pageTerminal.classList.toggle('hidden', t !== 'terminal');
  pageSettings.classList.toggle('hidden', t !== 'settings');

  if (t === 'files' || t === 'settings' || t === 'terminal') {
    abortInFlight();
    if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
  } else {
    restartPolling();
  }

  if (t === 'files') {
    if (!state.fmInit) { fm.init(); } else { fm.list(); }
  } else if (t === 'terminal') {
    const boot = () => {
      if (window.term && typeof window.term.initOnce === 'function') {
        window.term.initOnce();
        window.term._requestFit();
        if (!window.term.active) {
          setTimeout(() => {
            window.term.ensure().then(() => window.term._maybeResizePost());
          }, 50);
        } else {
          window.term._maybeResizePost();
        }
      } else {
        setTimeout(boot, 50);
      }
    };
    boot();
  } else if (t === 'settings') {
    cfg.load();
  }

  if (!suppressHash) {
    const nh = '#' + t;
    if (location.hash !== nh) location.hash = nh;
  }
}

window.addEventListener('hashchange', () => {
  suppressHash = true;
  setTab(tabFromHash());
  suppressHash = false;
});

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    abortInFlight();
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  } else {
    if (state.activeTab !== 'files' && state.activeTab !== 'settings' && state.activeTab !== 'terminal') {
      restartPolling();
    }
  }
});

// サーバーのスペック表示用
const sysSpec = document.getElementById('sysSpec');

function renderStaticSpecs() {
  const entries = [
    ['Server App', STATIC_INFO.ServerApp],
    ['PHP Version', STATIC_INFO.PHPVersion],
    ['Domain', STATIC_INFO.Domain],
    ['OS', STATIC_INFO.OS],
    ['Host', STATIC_INFO.Host],
    ['Kernel', STATIC_INFO.Kernel],
    ['Shell', STATIC_INFO.Shell || '--'],
    ['CPU', STATIC_INFO.CPU],
    ['Memory', STATIC_INFO.Memory],
    ['Swap', STATIC_INFO.Swap],
    ['GPU', STATIC_INFO.GPU],
    ['Disk', STATIC_INFO.Disk],
  ];

  sysSpec.innerHTML = '';

  for (const [k, v] of entries) {
    const div = document.createElement('div');
    div.innerHTML = `<div class="text-xs text-slate-400">${escapeHtml(k)}</div><div class="mono break-words">${escapeHtml(v || '--')}</div>`;
    sysSpec.appendChild(div);
  }
}

// ポーリングするところ(800msごとに更新してる)
function restartPolling() {
  abortInFlight();
  if (state.pollTimer) clearInterval(state.pollTimer);
  tick();
  state.pollTimer = setInterval(tick, POLL_MS);
}

async function tick() {
  if (state.inFlight) return;
  state.inFlight = true;
  state.controller = new AbortController();
  const { signal } = state.controller;

  try {
    if (state.activeTab === 'overview') {
      const res = await fetch('?action=summary', { cache: 'no-store', signal });
      const j = await res.json();
      if (j.ok) renderOverview(j);
    } else if (state.activeTab === 'procs') {
      const res = await fetch('?action=processes', { cache: 'no-store', signal });
      const j = await res.json();
      if (j.ok) {
        state.procs = j.processes || [];
        renderProcesses();
      }
    }
  } catch (e) {
  } finally {
    state.inFlight = false;
    state.controller = null;
  }
}

const cpuTotalPct = document.getElementById('cpuTotalPct');
const cpuModel = document.getElementById('cpuModel');
const cpuChart = document.getElementById('cpuChart');
const memText = document.getElementById('memText');
const memBar = document.getElementById('memBar');
const memChart = document.getElementById('memChart');
const loadText = document.getElementById('loadText');
const loadChart = document.getElementById('loadChart');
const platformText = document.getElementById('platformText');
const coresGrid = document.getElementById('coresGrid');
const gpuSummary = document.getElementById('gpuSummary');
const gpuCharts = document.getElementById('gpuCharts');

function renderOverview(j) {
  platformText.textContent = `(c) 2025 ActiveTK. Released under the MIT License. - ${j.platform} @ ${new Date(j.timestamp * 1000).toLocaleTimeString()}`;

  const total = j.cpu?.total || null;
  const cores = j.cpu?.cores || [];

  cpuModel.textContent = j.cpu?.model || '';

  let totalPct = null;
  if (state.lastCpu) totalPct = computeCpuPct(state.lastCpu.total, total);

  state.lastCpuPrev = { total, cores };
  coresGrid.innerHTML = '';

  const prevCores = state.lastCpu?.cores || [];
  for (let i = 0; i < cores.length; i++) {
    let pct = null;
    if (prevCores[i]) pct = computeCpuPct(prevCores[i], cores[i]);

    const div = document.createElement('div');
    div.className = 'p-3 rounded bg-slate-800/40 border border-slate-800';
    div.innerHTML =
      `<div class="text-xs text-slate-400">CPU${i}</div> ` +
      `<div class="text-lg mono">${pct == null ? '--%' : pct.toFixed(1) + '%'}</div> ` +
      `<div class="w-full h-1.5 bg-slate-700 rounded mt-2">` +
      `<div class="h-1.5 bg-sky-500 rounded" style="width:${pct ? clamp(pct, 0, 100) : 0}%"></div>` +
      `</div>`;

    coresGrid.appendChild(div);
  }

  state.lastCpu = { total, cores };

  if (totalPct == null) totalPct = 0;
  cpuTotalPct.textContent = fmtPct(totalPct);

  ringPush(state.series.cpuTotal, totalPct, state.seriesMaxPoints);
  drawLine(cpuChart, state.series.cpuTotal, 100);

  const kbTotal = j.memory?.kb_total ?? null;
  const kbUsed = j.memory?.kb_used ?? null;
  const memPct = (kbTotal && kbTotal > 0 && kbUsed != null) ? (kbUsed / kbTotal) * 100 : null;

  memText.textContent = `${bytesHum(kbUsed)} / ${bytesHum(kbTotal)}`;
  memBar.style.width = `${memPct ? clamp(memPct, 0, 100) : 0}%`;

  ringPush(state.series.memPct, memPct || 0, state.seriesMaxPoints);
  drawLine(memChart, state.series.memPct, 100);

  const l1 = j.loadavg ? j.loadavg['1'] : null;
  loadText.textContent = `${l1 ?? '--'} / ${j.loadavg ? j.loadavg['5'] : '--'} / ${j.loadavg ? j.loadavg['15'] : '--'}`;
  ringPush(state.series.load1, l1 || 0, state.seriesMaxPoints);

  const yMaxLoad = Math.max(1, (cores?.length || 1));
  drawLine(loadChart, state.series.load1, yMaxLoad);

  const g = j.gpus || [];
  if (g.length === 0) {
    gpuSummary.textContent = '検出なし';
    gpuCharts.innerHTML = '';
  } else {
    gpuSummary.textContent = g.map(x => `#${x.index} ${x.name} ${x.util_percent ?? '--'}%`).join(' | ');
    gpuCharts.innerHTML = '';
    g.forEach((gpu) => {
      const key = (gpu.vendor || 'gpu') + ':' + (gpu.index ?? gpu.name);
      if (!state.series.gpu[key]) state.series.gpu[key] = [];
      ringPush(state.series.gpu[key], gpu.util_percent ?? 0, state.seriesMaxPoints);

      const wrap = document.createElement('div');
      wrap.innerHTML =
        `<div class="text-xs text-slate-300 mono mb-1">#${gpu.index} ${gpu.name} ${gpu.util_percent ?? '--'}% ${gpu.mem_used_mb != null && gpu.mem_total_mb != null ? `/ ${gpu.mem_used_mb}/${gpu.mem_total_mb} MB` : ''}</div><canvas></canvas>`;
      gpuCharts.appendChild(wrap);
      drawLine(wrap.querySelector('canvas'), state.series.gpu[key], 100);
    });
  }
}

const procBody = document.getElementById('procBody');
const sortLabel = document.getElementById('sortLabel');
const procCount = document.getElementById('procCount');

function renderProcesses() {
  const key = state.sortKey, dir = state.sortDir;
  const arr = state.procs.slice();

  arr.sort((a, b) => {
    const va = a[key], vb = b[key];
    if (typeof va === 'number' && typeof vb === 'number') return dir === 'asc' ? va - vb : vb - va;
    return dir === 'asc' ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
  });

  sortLabel.textContent = `${key} ${dir === 'asc' ? '▲' : '▼'}`;
  procCount.textContent = `プロセス数: ${arr.length}`;

  procBody.innerHTML = '';
  const frag = document.createDocumentFragment();

  for (const p of arr) {
    const stopped = ((p.state || '').toUpperCase().indexOf('T') !== -1);
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-800/50';
    tr.innerHTML =
      ` <td class="p-2 mono">${p.pid}</td>` +
      ` <td class="p-2 truncate" title="${escapeHtml(p.command || '')}">${escapeHtml(p.title || '')}</td>` +
      ` <td class="p-2">${escapeHtml(p.user || '')}</td>` +
      ` <td class="p-2 mono">${p.cpu_percent == null ? '--' : p.cpu_percent.toFixed(1)}</td>` +
      ` <td class="p-2 mono">${p.mem_percent == null ? '--' : p.mem_percent.toFixed(1)}</td>` +
      ` <td class="p-2 mono">${fmtMiB(p.rss_kb)}</td>` +
      ` <td class="p-2 mono">${escapeHtml(p.state || '')}</td>` +
      ` <td class="p-2 mono">${p.nice == null ? '' : p.nice}</td>` +
      ` <td class="p-2 mono">${p.priority == null ? '' : p.priority}</td>` +
      ` <td class="p-2 mono">${escapeHtml(p.elapsed || '')}</td>` +
      ` <td class="p-2"> ` +
      ` <div class="flex gap-2"> ` +
      `${(!IS_WINDOWS) ? (stopped ? `<button data-act="CONT" data-pid="${p.pid}" class="px-2 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-xs">再開</button>` : `<button data-act="STOP" data-pid="${p.pid}" class="px-2 py-1 rounded bg-amber-600 hover:bg-amber-500 text-xs">停止</button>`) : ''}` +
      ` <button data-act="TERM" data-pid="${p.pid}" class="px-2 py-1 rounded bg-sky-600 hover:bg-sky-500 text-xs">終了</button>` +
      ` <button data-act="KILL" data-pid="${p.pid}" class="px-2 py-1 rounded bg-rose-600 hover:bg-rose-500 text-xs">強制終了</button>` +
      ` </div> </td>`;

    frag.appendChild(tr);
  }

  procBody.appendChild(frag);
}

document.querySelectorAll('thead th[data-key]').forEach(th => {
  th.addEventListener('click', () => {
    const k = th.getAttribute('data-key');
    if (state.sortKey === k) {
      state.sortDir = (state.sortDir === 'asc') ? 'desc' : 'asc';
    } else {
      state.sortKey = k;
      state.sortDir = 'asc';
    }
    renderProcesses();
  });
});

procBody.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const pid = btn.getAttribute('data-pid');
  const act = btn.getAttribute('data-act');
  try {
    const res = await fetch(`?action=signal&pid=${encodeURIComponent(pid)}&sig=${encodeURIComponent(act)}`, { method: 'POST' });
    const j = await res.json();
    btn.title = j.ok ? 'OK' : ('Error: ' + (j.error || ''));
    setTimeout(() => {
      if (!state.inFlight) tick();
    }, 250);
  } catch { }
});

const fm = {
  init() {
    state.fmInit = true;
    const root = document.getElementById('fm-root').value;
    document.getElementById('fm-linkto').value = root.replace(/\/?$/, '/') + 'example.atkfm-link';
    this.list();
    setFMHeight();
  },

  info(msg, type) {
    const el = document.getElementById('fmInfo');
    if (!el) return;
    el.textContent = String(msg ?? '');
    const base = 'ml-3 text-base font-medium tracking-wide ';
    const color = type === 'error' ? 'text-rose-300' : type === 'ok' ? 'text-emerald-300' : 'text-slate-100';
    el.className = base + color;
  },

  debug(msg) {
    document.getElementById('fmDebug').textContent = msg || '';
  },

  async list() {
    const root = document.getElementById('fm-root').value;
    if (root.slice(-1) !== '/' && !/\.(zip|7z)$/i.test(root)) {
      document.getElementById('fm-root').value = root + '/';
    }
    try {
      const url = `?ajax-typeof=get-directory&ajax-option=${encodeURIComponent(document.getElementById('fm-root').value)}`;
      const res = await fetch(url, { cache: 'no-store' });
      const data = await res.json();
      this.renderList(data);
    } catch (e) {
      this.info('エラー: データを更新できませんでした。', 'error');
    }
  },

  renderList(e) {
    // ここは無理やり詰め込んだのであとで綺麗にしたい
    const box = document.getElementById('fm-list');
    box.innerHTML = '';

    if (e['atk-fm-error']) {
      this.info(e['atk-fm-error'], 'error');
      return;
    }

    const entries = Object.entries(e);
    if (entries.length === 0) {
      this.info('(空ディレクトリです)');
      return;
    }

    const frag = document.createDocumentFragment();

    for (const [path, type] of entries) {
      const base = path.split('/').pop();
      const div = document.createElement('div');
      div.className = 'py-1 flex items-center gap-2';

      if (type === 'a') { // regular file
        div.innerHTML =
          `<span>📄 ${escapeHtml(base)}</span> ` +
          `<a class="atkfm-underline" href="?ajax-typeof=get-item&ajax-option=${encodeURIComponent(path)}" target="_blank" rel="noopener noreferrer"><span class="atkfm-btn">開く</span></a> ` +
          `<button class="atkfm-btn" data-act="modal" data-path="${escapeHtml(path)}">操作</button>`;
      } else if (type === 'b') { // directory
        div.innerHTML =
          `<span>📁 ${escapeHtml(base)} (フォルダー)</span> ` +
          `<button class="atkfm-btn atkfm-btn--accent" data-act="cd" data-path="${escapeHtml(path)}">開く</button> ` +
          `<button class="atkfm-btn atkfm-btn--danger" data-act="rmdir" data-path="${escapeHtml(path)}">削除</button> ` +
          `<button class="atkfm-btn" data-act="zip" data-path="${escapeHtml(path)}">圧縮</button> ` +
          `<button class="atkfm-btn" data-act="rename" data-path="${escapeHtml(path)}">リネーム</button> ` +
          `<button class="atkfm-btn" data-act="copyd" data-path="${escapeHtml(path)}">コピー</button> ` +
          `<button class="atkfm-btn" data-act="count" data-path="${escapeHtml(path)}">詳細</button>`;
      } else if (type === 'c') { // archive
        div.innerHTML =
          `<span>🗜️ ${escapeHtml(base)} (zip他)</span> ` +
          `<button class="atkfm-btn atkfm-btn--accent" data-act="cd" data-path="${escapeHtml(path)}">プレビュー</button> ` +
          `<button class="atkfm-btn" data-act="unzip" data-path="${escapeHtml(path)}">展開</button> ` +
          `<button class="atkfm-btn" data-act="modal" data-path="${escapeHtml(path)}">操作</button>`;
      } else if (type === 'd') { // inside zip
        div.innerHTML =
          `<span>📦 ${escapeHtml(base)} (zip内)</span> ` +
          `<a class="atkfm-underline" href="?ajax-typeof=get-item-zip&ajax-option=${encodeURIComponent(document.getElementById('fm-root').value)}&ajax-option2=${encodeURIComponent(path)}" target="_blank" rel="noopener noreferrer"><span class="atkfm-btn">表示</span></a> ` +
          `<button class="atkfm-btn atkfm-btn--danger" data-act="rmzip" data-path="${escapeHtml(path)}">削除</button>`;
      } else if (type === 'e') { // link
        div.innerHTML =
          `<span>🔗 ${escapeHtml(base)} (リンク)</span> ` +
          `<button class="atkfm-btn atkfm-btn--accent" data-act="link-move" data-path="${escapeHtml(path)}">移動</button> ` +
          `<button class="atkfm-btn" data-act="link-show" data-path="${escapeHtml(path)}">リンク先表示</button> ` +
          `<button class="atkfm-btn" data-act="rename" data-path="${escapeHtml(path)}">リネーム</button> ` +
          `<button class="atkfm-btn atkfm-btn--danger" data-act="rm" data-path="${escapeHtml(path)}">削除</button>`;
      } else if (type === 'f') { // encrypted
        div.innerHTML =
          `<span>🔒 ${escapeHtml(base)} (暗号ファイル)</span> ` +
          `<button class="atkfm-btn" data-act="decrypt" data-path="${escapeHtml(path)}">復号化</button> ` +
          `<a class="atkfm-underline" href="?ajax-typeof=download-item&ajax-option=${encodeURIComponent(path)}" target="_blank" rel="noopener noreferrer"><span class="atkfm-btn">ダウンロード</span></a> ` +
          `<button class="atkfm-btn" data-act="modal" data-path="${escapeHtml(path)}">操作</button>`;
      } else {
        div.textContent = `(未対応) ${path}`;
      }

      frag.appendChild(div);
    }

    box.appendChild(frag);
  },

  async up() {
    const root = document.getElementById('fm-root').value.replace(/\/$/, '');
    const up = root.substring(0, root.lastIndexOf('/')) || '/';
    document.getElementById('fm-root').value = up.endsWith('/') ? up : up + '/';
    this.list();
  },

  async count(path) {
    const p = path || document.getElementById('fm-root').value;
    try {
      const res = await fetch(`?ajax-typeof=count-directory-files&ajax-option=${encodeURIComponent(p)}`);
      const j = await res.json();
      this.info(`${j.File}個のファイル、${j.Directory}個のディレクトリ。計測時間:${j.Time.toFixed(3)}秒、サイズ:${j.SIZE}`);
    } catch {
      this.info('エラー: 詳細取得に失敗');
    }
  },

  viewList() {
    const p = document.getElementById('fm-root').value;
    window.open(`?ajax-typeof=list-view&ajax-option=${encodeURIComponent(p)}`, '_blank');
  },

  async addFile() {
    const name = document.getElementById('fm-add-file').value.trim();
    if (!name) {
      this.info('ファイル名が空');
      return;
    }
    const res = await fetch(`?ajax-typeof=add-item&ajax-option=${encodeURIComponent(name)}`);
    await res.text();
    this.info('ファイルを新規作成しました。');
    this.list();
  },

  async addDir() {
    const name = document.getElementById('fm-add-dir').value.trim();
    if (!name) {
      this.info('ディレクトリ名が空');
      return;
    }
    await fetch(`?ajax-typeof=add-directory&ajax-option=${encodeURIComponent(name)}`);
    this.info('ディレクトリを新規作成しました。');
    this.list();
  },

  async upload() {
    const files = document.getElementById('fm-upload-files').files;
    if (!files.length) {
      this.info('ファイル未選択');
      return;
    }
    const body = new FormData();
    for (const f of files) {
      body.append('file[]', f);
    }
    this.info('アップロードしています…');
    const res = await fetch(`?ajax-typeof=upload-item`, { method: 'POST', body });
    const t = await res.text();
    this.info(t);
    this.list();
  },

  async chunkUpload() {
    const f = document.getElementById('fm-chunk-file').files[0];
    if (!f) {
      this.info('ファイル未選択');
      return;
    }
    const sizeMB = parseInt(document.getElementById('fm-chunk-mb').value || '3', 10);
    const chunk = Math.max(1, sizeMB) * 1024 * 1024;
    const totalParts = Math.ceil(f.size / chunk);
    for (let i = 0; i < totalParts; i++) {
      const body = new FormData();
      body.append('data', f.slice(i * chunk, (i + 1) * chunk));
      body.append('filename', f.name);
      try {
        const res = await fetch(`?ajax-typeof=min-upload-item`, { method: 'POST', body, cache: 'no-cache' });
        await res.json();
        this.debug(`Upload %: ${Math.ceil(100 * (i + 1) / totalParts)}\nUploaded/Total: ${i + 1}/${totalParts}`);
        this.info(`ファイルを分割アップロードしています…(${Math.ceil(100 * (i + 1) / totalParts)}%完了)`);
      } catch (e) {
        this.info('エラー: 分割アップロードに失敗');
        return;
      }
      await new Promise(r => setTimeout(r, 10));
    }
    const endBody = new FormData();
    endBody.append('FileName', f.name);
    try {
      await fetch(`?ajax-typeof=min-upload-item&ajax-option=remove-upload-info`, { method: 'POST', body: endBody });
    } catch { }
    this.info('ファイルを分割アップロードしました！');
    document.getElementById('fm-chunk-file').value = '';
    this.list();
  },

  async uploadFromUrl() {
    const u = document.getElementById('fm-url').value.trim();
    if (!u) {
      this.info('URL未入力');
      return;
    }
    const res = await fetch(`?ajax-typeof=uploadfromurl&ajax-option=${encodeURIComponent(u)}`);
    const t = await res.text();
    this.info(t);
    this.list();
  },

  async makeLink() {
    const link = document.getElementById('fm-linkto').value.trim();
    if (!link) {
      this.info('リンク先未指定');
      return;
    }
    const res = await fetch(`?ajax-typeof=create-link&ajax-option=${encodeURIComponent(link)}`);
    await res.text();
    this.info('リンクを作成しました。');
    this.list();
  },

  async handleListClick(e) {
    const btn = e.target.closest('button');
    if (!btn) return;
    const act = btn.getAttribute('data-act');
    const path = btn.getAttribute('data-path');

    if (act === 'cd') {
      document.getElementById('fm-root').value = path.endsWith('/') ? path : (/\.(zip|7z)$/i.test(path) ? path : path + '/');
      this.list();
    } else if (act === 'rmdir') {
      if (!confirm('ディレクトリを削除しますか？')) return;
      await fetch(`?ajax-typeof=remove-directory&ajax-option=${encodeURIComponent(path)}`);
      this.info('ディレクトリを削除しました。');
      this.list();
    } else if (act === 'zip') {
      await fetch(`?ajax-typeof=make-zip&ajax-option=${encodeURIComponent(path)}`);
      this.info('フォルダーを圧縮しました。');
      this.list();
    } else if (act === 'rename') {
      const n = prompt('パスを入力してください', path);
      if (!n) return;
      await fetch(`?ajax-typeof=rename-item&ajax-option=${encodeURIComponent(path)}&ajax-option2=${encodeURIComponent(n)}`);
      this.info('ファイル名を変更しました。');
      this.list();
    } else if (act === 'copyd') {
      await fetch(`?ajax-typeof=copy-item&ajax-option=${encodeURIComponent(path)}`);
      this.info('ディレクトリをコピーしました。');
      this.list();
    } else if (act === 'count') {
      this.count(path);
    } else if (act === 'unzip') {
      const res = await fetch(`?ajax-typeof=open-zip&ajax-option=${encodeURIComponent(path)}`);
      this.info(await res.text());
      this.list();
    } else if (act === 'rmzip') {
      if (!confirm('削除しますか？')) return;
      const base = document.getElementById('fm-root').value;
      await fetch(`?ajax-typeof=remove-item-zip&ajax-option=${encodeURIComponent(base)}&ajax-option2=${encodeURIComponent(path)}`);
      this.info('削除しました。');
      this.list();
    } else if (act === 'link-move') {
      const res = await fetch(`?ajax-typeof=get-linkto&ajax-option=${encodeURIComponent(path)}`);
      const t = await res.text();
      if (t) {
        document.getElementById('fm-root').value = decodeURIComponent(t);
        this.list();
      }
    } else if (act === 'link-show') {
      const res = await fetch(`?ajax-typeof=get-linkto&ajax-option=${encodeURIComponent(path)}`);
      this.info('リンク先: ' + decodeURIComponent(await res.text()));
    } else if (act === 'decrypt') {
      const pw = prompt('【ファイル複合化】パスワードを入力してください。');
      if (!pw) { this.info('キャンセル'); return; }
      const res = await fetch(`?ajax-typeof=decrypt-item&ajax-option=${encodeURIComponent(path)}&ajax-option2=${encodeURIComponent(pw)}`);
      this.info(await res.text());
      this.list();
    } else if (act === 'modal') {
      this.openModal(path);
    } else if (act === 'rm') {
      if (!confirm('ファイルを削除しますか？')) return;
      await fetch(`?ajax-typeof=remove-item&ajax-option=${encodeURIComponent(path)}`);
      this.info('削除しました。');
      this.list();
    }
  },

  openModal(path) {
    document.getElementById('fm-selected').value = path;
    const box = document.getElementById('fm-actions');
    const encPath = encodeURIComponent(path);

    const linkBtn = (label, href, extra = '') => `<a class="atkfm-underline atkfm-btn w-full ${extra}" href="${href}" target="_blank" rel="noopener noreferrer" onclick="fm.closeModal()">${label}</a>`;
    const actBtn = (label, handler, extra = '') => `<button class="atkfm-btn w-full ${extra}" onclick="fm.closeModal(); ${handler}">${label}</button>`;

    box.innerHTML = [
      linkBtn('開く', `?ajax-typeof=get-item&ajax-option=${encPath}`, 'atkfm-btn--accent'),
      actBtn('削除', `fm.deleteSel();`, 'atkfm-btn--danger'),
      linkBtn('読み取り専用', `?ajax-typeof=get-item&readonly=true&ajax-option=${encPath}`),
      linkBtn('HTML表示', `?ajax-typeof=view-html&ajax-option=${encPath}`),
      linkBtn('バイナリ表示', `?ajax-typeof=view-hex&ajax-option=${encPath}`),
      linkBtn('ダウンロード', `?ajax-typeof=download-item&ajax-option=${encPath}`),
      actBtn('リネーム', `fm.renameSel();`),
      actBtn('コピー', `fm.copySel();`),
      actBtn('ファイルサイズ取得', `fm.sizeSel();`),
      actBtn('md5ハッシュ表示', `fm.md5Sel();`),
      actBtn('暗号化', `fm.encryptSel();`)
    ].map(x => `<div>${x}</div>`).join('');

    const modal = document.getElementById('fm-modal');
    modal.classList.remove('hidden');
    document.getElementById('fm-modal-backdrop').onclick = () => this.closeModal();

    document.addEventListener('keydown', escCloser);
    function escCloser(e) {
      if (e.key === 'Escape') {
        fm.closeModal();
        document.removeEventListener('keydown', escCloser);
      }
    }
  },

  closeModal() {
    document.getElementById('fm-modal').classList.add('hidden');
  },

  async renameSel() {
    const p = document.getElementById('fm-selected').value;
    const n = prompt('パスを入力してください', p);
    if (!n) return;
    await fetch(`?ajax-typeof=rename-item&ajax-option=${encodeURIComponent(p)}&ajax-option2=${encodeURIComponent(n)}`);
    this.closeModal();
    this.info('リネームしました。');
    this.list();
  },

  async copySel() {
    const p = document.getElementById('fm-selected').value;
    await fetch(`?ajax-typeof=copy-item&ajax-option=${encodeURIComponent(p)}`);
    this.closeModal();
    this.info('コピーしました。');
    this.list();
  },

  async sizeSel() {
    const p = document.getElementById('fm-selected').value;
    fm.closeModal();
    const res = await fetch(`?ajax-typeof=get-filesize&ajax-option=${encodeURIComponent(p)}`);
    this.info('ファイルのサイズ: ' + await res.text());
  },

  async md5Sel() {
    const p = document.getElementById('fm-selected').value;
    fm.closeModal();
    const res = await fetch(`?ajax-typeof=get-filemd5&ajax-option=${encodeURIComponent(p)}`);
    this.info('md5: ' + await res.text());
  },

  async encryptSel() {
    const p = document.getElementById('fm-selected').value;
    const pw = prompt('【ファイル暗号化】パスワードを入力してください。');
    if (!pw) { this.info('キャンセル'); return; }
    const res = await fetch(`?ajax-typeof=encrypt-item&ajax-option=${encodeURIComponent(p)}&ajax-option2=${encodeURIComponent(pw)}`);
    this.closeModal();
    this.info(await res.text());
    this.list();
  },

  async deleteSel() {
    const p = document.getElementById('fm-selected').value;
    if (!confirm('削除しますか？')) return;
    await fetch(`?ajax-typeof=remove-item&ajax-option=${encodeURIComponent(p)}`);
    this.closeModal();
    this.info('削除しました。');
    this.list();
  }
};

document.getElementById('fm-list').addEventListener('click', (e) => fm.handleListClick(e));

const cfg = {
  hasPassword: false,
  me: '',
  runAsRoot: false,
  serverUser: '',

  async load() {
    try {
      const r = await fetch('?action=config-get', { cache: 'no-store' });
      const j = await r.json();
      if (!j.ok) throw new Error('config-get failed');

      this.hasPassword = !!j.hasPassword;
      this.me = j.clientIp || '';
      this.runAsRoot = !!j.runAsRoot;
      this.serverUser = j.serverUser || '';

      const ta = document.getElementById('cfg-ip-allow');
      if (ta) ta.value = (j.ipAllow || []).join('\n');

      const meEl = document.getElementById('cfg-ip-me');
      if (meEl) meEl.textContent = `現在の接続IP: ${this.me}`;

      const ipInfo = document.getElementById('cfg-ip-info');
      if (ipInfo) ipInfo.textContent = '';

      const passInfo = document.getElementById('cfg-pass-info');
      if (passInfo) passInfo.textContent = '';

      const cbRoot = document.getElementById('cfg-run-root');
      if (cbRoot) cbRoot.checked = this.runAsRoot;

      const ex = document.getElementById('cfg-sudoers-example');
      if (ex) {
        const u = (this.serverUser || 'apache');
        ex.textContent = `${u} ALL=(ALL) NOPASSWD: /bin/*, /usr/bin/*, /usr/sbin/*`;
      }

      const info = document.getElementById('cfg-run-root-info');
      if (info) info.textContent = this.runAsRoot ? '現在: root 権限で動作（tmux/シェル）' : '現在: 通常権限で動作';
    } catch {
      const passInfo = document.getElementById('cfg-pass-info');
      if (passInfo) passInfo.textContent = '設定の取得に失敗しました。';
    }
  },

  async savePassword(clear = false) {
    const info = document.getElementById('cfg-pass-info');
    if (info) info.textContent = '保存中...';

    const npwEl = document.getElementById('cfg-pass-new');
    const npw = npwEl ? npwEl.value : '';
    if (!clear && npw.length === 0) {
      if (info) info.textContent = '新しいパスワードが空です。';
      return;
    }

    const body = clear ? { change: 'password-clear' } : { change: 'password', newPassword: npw };

    try {
      const r = await fetch('?action=config-set', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const j = await r.json();
      if (j.ok) {
        if (info) info.textContent = clear ? 'パスワードを削除しました。' : 'パスワードを更新しました。';
        if (npwEl) npwEl.value = '';
        this.load();
      } else {
        if (info) info.textContent = 'エラー: ' + (j.error || '失敗しました');
      }
    } catch {
      if (info) info.textContent = 'エラー: 通信に失敗しました。';
    }
  },

  async saveIp() {
    const info = document.getElementById('cfg-ip-info');
    if (info) info.textContent = '保存中…';
    const ta = document.getElementById('cfg-ip-allow');
    const list = ta ? ta.value.split(/\r?\n/).map(s => s.trim()) : [];
    try {
      const r = await fetch('?action=config-set', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ change: 'ip', ipAllow: list }) });
      const j = await r.json();
      if (j.ok) {
        if (info) info.textContent = 'IP許可リストを更新しました。';
        if (ta) ta.value = (j.ipAllow || []).join('\n');
      } else {
        if (info) info.textContent = 'エラー: ' + (j.error || '失敗しました');
      }
    } catch {
      if (info) info.textContent = 'エラー: 通信に失敗しました。';
    }
  },

  async saveRunRoot() {
    const cb = document.getElementById('cfg-run-root');
    const info = document.getElementById('cfg-run-root-info');
    if (info) info.textContent = '保存中…';
    try {
      const r = await fetch('?action=config-set', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ change: 'run-as-root', enabled: !!cb.checked })
      });
      const j = await r.json();
      if (j.ok) {
        this.runAsRoot = !!j.runAsRoot;
        if (info) info.textContent = this.runAsRoot ? '現在: root 権限で動作（tmux/シェル）' : '現在: 通常権限で動作';
      } else {
        if (info) info.textContent = 'エラー: ' + (j.error || '失敗しました');
        cb.checked = !cb.checked; // ロールバック
      }
    } catch {
      if (info) info.textContent = 'エラー: 通信に失敗しました。';
      cb.checked = !cb.checked; // ロールバック
    }
  },
};

document.getElementById('cfg-pass-save').addEventListener('click', () => cfg.savePassword(false));
document.getElementById('cfg-pass-clear').addEventListener('click', () => cfg.savePassword(true));
document.getElementById('cfg-ip-save').addEventListener('click', () => cfg.saveIp());
document.getElementById('cfg-ip-add-self').addEventListener('click', () => {
  if (!cfg.me) return;
  const ta = document.getElementById('cfg-ip-allow');
  const lines = ta.value.split(/\r?\n/);
  if (!lines.some(l => l.trim() === cfg.me)) {
    lines.push(cfg.me);
    ta.value = lines.join('\n');
  }
});
const cbRootEl = document.getElementById('cfg-run-root');
if (cbRootEl) cbRootEl.addEventListener('change', () => cfg.saveRunRoot());

renderStaticSpecs();

suppressHash = true;
const firstTab = tabFromHash();
if (firstTab === 'terminal') {
  window.addEventListener('load', () => setTab('terminal'));
} else {
  setTab(firstTab);
}
suppressHash = false;

function setFMHeight() {
  const wrap = document.querySelector('#pageFiles .atkfm-wrap');
  if (!wrap) return;
  const rect = wrap.getBoundingClientRect();
  const top = rect.top + window.scrollY;
  const inner = window.innerHeight;
  const bottomPadding = 16;
  const h = Math.max(240, inner - rect.top - bottomPadding);
  wrap.style.height = h + 'px';
}

window.addEventListener('resize', setFMHeight);
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) setFMHeight();
});

const term = {
  _inited: false,
  xterm: null,
  fit: null,

  mode: 'tmux',
  tabs: [],
  active: null,
  pollTimer: null,
  _polling: false,
  lastScreenB64: '',
  lastCx: null,
  lastCy: null,

  sendBuf: '',
  sendTimer: null,

  basicSid: null,
  basicCwd: null,
  lineBuf: '',
  basicNoticeShown: false,

  fontSize: parseInt(localStorage.getItem('atkfm_term_font') || '14', 10),

  _log(...a){ if (window.ATKFM_DEBUG) console.debug('[term]', ...a); },
  _err(m){ console.error(m); try{ this.xterm?.writeln('\r\n\x1b[31m[ERROR]\x1b[0m '+m);}catch{} },

  _readCookie(name){
    return decodeURIComponent((document.cookie.split('; ').find(s=>s.startsWith(name+'='))||'')
      .split('=').slice(1).join('=')||'');
  },
  async _ensureCsrfReady(deadlineMs=2000){
    const t0 = performance.now();
    while (!this._readCookie('ATKFM_CSRF') && (performance.now()-t0) < deadlineMs){
      await new Promise(r=>setTimeout(r, 25));
    }
  },
  _csrf(){
    if (this.__csrf) return this.__csrf;
    const token = this._readCookie('ATKFM_CSRF') || '';
    this.__csrf = { token, headerName: 'X-CSRF-Token' };
    return this.__csrf;
  },
  _withCsrfHeaders(h = {}){
    const {token, headerName} = this._csrf();
    const headers = { 'X-Requested-With':'XMLHttpRequest', ...h };
    if (token) headers[headerName] = token;
    return headers;
  },
  async _fetchJSON(url, opts={}, timeoutMs=10000){
    const ac = new AbortController();
    const timer = setTimeout(()=>ac.abort(), timeoutMs);
    const isPost = String((opts.method||'GET')).toUpperCase()==='POST';
    if (isPost) await this._ensureCsrfReady();
    try{
      const r = await fetch(url, {
        credentials:'same-origin',
        cache:'no-store',
        ...opts,
        headers: this._withCsrfHeaders(opts.headers||{}),
        signal: ac.signal
      });
      const ct = (r.headers.get('content-type')||'').toLowerCase();
      if (!ct.includes('application/json')) throw new Error('bad content-type: '+ct);
      let j = await r.json();

      if (!j.ok && j.error === 'bad csrf token' && isPost && !opts._retried){
        await this._ensureCsrfReady();
        return await this._fetchJSON(url, {...opts, _retried:true}, timeoutMs);
      }
      return j;
    } finally { clearTimeout(timer); }
  },
  async _fetchJSONForm(url, formData, timeoutMs=10000){
    return await this._fetchJSON(url, {method:'POST', body: formData}, timeoutMs);
  },

  _renderCapture(out_b64, cy, cx, h, w){
    const raw = base64ToUtf8(out_b64).replace(/\x1c|\x1d|\x1e|\x1f|\x0c/g, ''); // \x0c は既存同様、他の不可視制御も念のため除去
    const lines = raw.split('\n');

    const height = Math.max(1, h|0);
    const width  = Math.max(1, w|0);

    let esc = '\x1b[0m\x1b[H\x1b[2J';

    for (let i = 0; i < height; i++){
      const ln = lines[i] ?? '';
      const clipped = ln.length > width ? ln.slice(0, width) : ln;
      esc += `\x1b[${i+1};1H${clipped}\x1b[0m\x1b[K`;
    }

    esc += '\x1b[0m';

    if (Number.isInteger(cy) && Number.isInteger(cx)){
      esc += `\x1b[${(cy|0)+1};${(cx|0)+1}H`;
      this.lastCy = cy|0;
      this.lastCx = cx|0;
    }

    if (typeof this.xterm.writeSync === 'function') this.xterm.writeSync(esc);
    else this.xterm.write(esc);
  },

  initOnce(){
    if (this._inited) return;
    this._inited = true;

    this.xterm = new window.Terminal({
      convertEol:false,
      fontSize:this.fontSize,
      fontFamily:'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
      cursorBlink:true,
      cursorStyle:'block',
      disableStdin:false,
      scrollback:5000,
      allowProposedApi:true
    });
    this.fit = new window.FitAddon.FitAddon();
    this.xterm.loadAddon(this.fit);
    this.xterm.open(document.getElementById('xterm'));
    this.fit.fit();
    this.xterm.focus();

    this.xterm.onData((data)=>{ this.mode==='tmux' ? this._enqueueSend(data) : this._handleBasicInput(data); });

    const fontSel = document.getElementById('term-font');
    if (fontSel){
      fontSel.value = String(this.fontSize);
      fontSel.addEventListener('change', ()=>{
        const px = parseInt(fontSel.value,10)||14;
        this.fontSize = px;
        localStorage.setItem('atkfm_term_font', String(px));
        this.xterm.options.fontSize = px;
        this._requestFit();
      });
    }

    const wrapEl = document.getElementById('xterm-wrap');
    let roQueued = false;
    const onResize = ()=>{
      if (roQueued) return;
      roQueued = true;
      requestAnimationFrame(()=>{
        roQueued = false;
        try{ this.fit.fit(); } finally { this._maybeResizePost(); }
      });
    };
    new ResizeObserver(onResize).observe(wrapEl);
    window.addEventListener('orientationchange', onResize);
    document.addEventListener('visibilitychange', ()=>{ if (!document.hidden) onResize(); });

    window.addEventListener('error', e=>this._err(String(e.error||e.message||'error')));
    window.addEventListener('unhandledrejection', e=>this._err('Promise rejection: '+(e.reason?.message||e.reason||'unknown')));
  },

  bindUI(){
    const newBtn = document.getElementById('term-newtab');
    if (newBtn) newBtn.addEventListener('click', ()=>this.newTab());
  },

  async ensure(){
    if (this.mode === 'tmux' && this.active) {
      this._renderTabs();
      this._startPollingTmux();
      this._maybeResizePost();
      return;
    }
    const ok = await this._tryOpenTmux();
    if (!ok && !this.basicSid) await this._enterBasicMode(false);
  },

  _enqueueSend(data){
    this.sendBuf += data;
    if (!this.sendTimer) this.sendTimer = setTimeout(()=>this._flushSend(), 30);
  },
  async _flushSend(){
    const chunk = this.sendBuf; this.sendBuf=''; clearTimeout(this.sendTimer); this.sendTimer=null;
    if (!chunk || !this.active) return;
    const j = await this._fetchJSON('?action=term2-write', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ sid:this.active, data_b64: utf8ToBase64(chunk) })
    }).catch(e=>this._err('write error: '+e.message));
    if (j && !j.ok) this._err(j.error||'write failed');
  },
  async _tryOpenTmux(){
    try{
      const cols = this.xterm.cols || 120, rows = this.xterm.rows || 30;
      const body = new FormData(); body.append('cols', String(cols)); body.append('rows', String(rows));
      const j = await this._fetchJSONForm('?action=term2-open', body);
      if (!j.ok) return false;

      this.mode = 'tmux';
      await this._refreshTmuxTabs();
      this.active = j.sid;
      this.lastScreenB64 = '';
      this._showBannerOnceFor(j.sid);
      this._renderTabs();
      this._startPollingTmux();
      this._maybeResizePost();
      return true;
    }catch(e){
      this._log('open tmux failed', e); return false;
    }
  },

  async _refreshTmuxTabs(){
    const j = await this._fetchJSON('?action=term2-list', {method:'GET'}).catch(e=>this._err('list tabs: '+e.message));
    if (j?.ok) this.tabs = j.tabs||[];
    this._renderTabs();
  },

  _renderTabs(){
    const box = document.getElementById('term-tabs'); if (!box) return;
    box.innerHTML = '';
    const frag = document.createDocumentFragment();

    if (this.mode==='tmux'){
      for (const t of this.tabs){
        const wrap = document.createElement('div'); wrap.className='flex items-center gap-1';
        const btn = document.createElement('button');
        btn.className = 'atkfm-btn' + (t.id===this.active ? ' atkfm-btn--accent' : '');
        btn.textContent = t.label; btn.title = t.label;
        btn.addEventListener('click', ()=>this._switchTmuxTab(t.id));
        const close = document.createElement('button');
        close.className='atkfm-btn atkfm-btn--danger'; close.textContent='×'; close.title='閉じる';
        close.addEventListener('click', (e)=>{ e.stopPropagation(); this._closeTmuxTab(t.id); });
        wrap.append(btn, close);
        frag.appendChild(wrap);
      }
    } else {
      const wrap = document.createElement('div'); wrap.className='flex items-center gap-1';
      const btn = document.createElement('button'); btn.className='atkfm-btn atkfm-btn--accent'; btn.textContent='basic';
      const close = document.createElement('button'); close.className='atkfm-btn atkfm-btn--danger'; close.textContent='×';
      close.addEventListener('click', ()=>this._enterBasicMode(true));
      wrap.append(btn, close); frag.appendChild(wrap);
    }
    box.appendChild(frag);

    const newBtn = document.getElementById('term-newtab');
    if (newBtn){ newBtn.disabled = (this.mode!=='tmux'); newBtn.title = newBtn.disabled ? 'tmux をインストールすると有効になります' : '新しいタブ'; }
  },

  async _switchTmuxTab(id){
    this.active = id; this.lastScreenB64='';
    this._renderTabs();
    this._startPollingTmux();
    this._maybeResizePost();
  },

  async _closeTmuxTab(id){
    try{
      const fd = new FormData(); fd.append('sid', id);
      await this._fetchJSONForm('?action=term2-close', fd);
    }catch(e){ this._log('close tab failed', e); }
    await this._refreshTmuxTabs();
    if (this.tabs.length){
      this.active = this.tabs[0].id; this.lastScreenB64='';
      this._startPollingTmux(); this._maybeResizePost();
    } else {
      this.active = null; this._stopPollingTmux(); this.xterm.reset();
    }
  },

  _stopPollingTmux(){ if (this.pollTimer){ clearTimeout(this.pollTimer); this.pollTimer=null; } this._polling=false; },

  _startPollingTmux(){
    this._stopPollingTmux();
    const poll = async ()=>{
      if (!this.active) return;
      try{
        const j = await this._fetchJSON(`?action=term2-read&sid=${encodeURIComponent(this.active)}&mode=screen`, {method:'GET'});
        if (!j.ok){ this._err(j.error||'read failed'); return; }

        const wantCols = (this.xterm?.cols|0) || 120;
        const wantRows = (this.xterm?.rows|0) || 30;
        if (((j.w|0) !== wantCols) || ((j.h|0) !== wantRows)) {
          await this._maybeResizePost();
        }

        const screenChanged = (j.out_b64 !== this.lastScreenB64);
        const cursorChanged = (
          (typeof j.cx === 'number' && j.cx !== this.lastCx) ||
          (typeof j.cy === 'number' && j.cy !== this.lastCy)
        );

        if (screenChanged){
          this.lastScreenB64 = j.out_b64;
          this._renderCapture(j.out_b64, j.cy, j.cx, j.h, j.w);
        } else if (cursorChanged){
          this._placeCursor(j.cy, j.cx);
          this.lastCx = j.cx|0;
          this.lastCy = j.cy|0;
        }
      }catch(e){
        this._err('read error: '+e.message);
      }
    };
    poll();
    this.pollTimer = setInterval(poll, 500);
  },

  _placeCursor(row, col){
    if (row==null || col==null) return;
    const r = Math.max(1, (parseInt(row,10)|0) + 1);
    const c = Math.max(1, (parseInt(col,10)|0) + 1);
    this.xterm.write(`\x1b[${r};${c}H`);
  },

  _showBannerOnceFor(sid){
    try{
      if (!sid) return;
      const key = 'atkfm_tmux_banner_'+sid;
      if (sessionStorage.getItem(key)) return;
      this.xterm.writeln('**********************************************************************');
      this.xterm.writeln('** Terminal - WebTaskmgr / ATK-FM v2.0.1');
      this.xterm.writeln('** (c) 2025 ActiveTK. All rights reserved.');
      this.xterm.writeln('**********************************************************************\r\n');
      sessionStorage.setItem(key, '1');
    }catch{}
  },

  async _enterBasicMode(resetOutput=false){
    this.mode='basic';
    this._stopPollingTmux();
    this.tabs=[]; this.active=null; this.lastScreenB64='';

    if (!this.basicSid){
      try{
        const fd = new FormData(); fd.append('label','basic');
        const j = await this._fetchJSONForm('?action=term-open', fd);
        if (j.ok){ this.basicSid=j.sid; this.basicCwd=j.tab?.cwd||'/'; }
        else { this.basicSid=null; this.basicCwd='/'; }
      }catch{ this.basicSid=null; this.basicCwd='/'; }
    }

    if (resetOutput) this.xterm.reset();

    if (!this.basicNoticeShown){
      this.xterm.writeln('**********************************************************************');
      this.xterm.writeln('** Terminal - WebTaskmgr / ATK-FM v2.0.1');
      this.xterm.writeln('** (c) 2025 ActiveTK. All rights reserved.');
      this.xterm.writeln('**********************************************************************');
      this.xterm.writeln('** tmuxが見つかりません。以下のコマンドでtmuxを導入すると、より多くの機能を利用できます。');
      this.xterm.writeln('** (apt) > sudo apt install -y tmux');
      this.xterm.writeln('** (yum) > sudo yum install -y tmux');
      this.xterm.writeln('**********************************************************************\r\n');
      this.basicNoticeShown = true;
    }

    this._renderTabs();
    this._writePrompt();
  },

  _promptString(){
    let d = (this.basicCwd || '/').toString();
    if (typeof IS_WINDOWS!=='undefined' && IS_WINDOWS){ if (!/[\\/]$/.test(d)) d += '\\'; }
    else { if (!/\/$/.test(d)) d += '/'; }
    const u = (typeof PROMPT_USER!=='undefined'?PROMPT_USER:'user');
    const h = (typeof PROMPT_HOST!=='undefined'?PROMPT_HOST:'host');
    return `[${u}@${h} ${d}]# `;
  },
  _writePrompt(){ this.xterm.write(this._promptString()); },

  async _runBasic(cmd){
    try{
      const j = await this._fetchJSON('?action=term-run', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          sid:this.basicSid||'',
          input:cmd,
          cols:this.xterm.cols||120,
          rows:this.xterm.rows||30
        })
      });

      if (j?.ok){
        if (typeof j.out==='string' && j.out.length){
          this.xterm.write(j.out.replace(/\n/g,'\r\n'));
          if (!/\r?\n$/.test(j.out)) this.xterm.write('\r\n');
        }
        if (j.cwd) this.basicCwd = j.cwd;
      } else {
        this._err(j?.error||'command failed');
      }
    } catch(e){
      this._err('network error: '+e.message);
    }
    this.xterm.write('\x1b[0m');
    this._writePrompt();
  },

  async _handleBasicInput(data){
    for (const ch of data){
      const code = ch.charCodeAt(0);

      if (ch === '\r' || ch === '\n'){
        const cmd = this.lineBuf.trim();
        this.xterm.write('\r\n');
        this.lineBuf = '';
        if (!cmd){ this._writePrompt(); continue; }
        await this._runBasic(cmd);
        continue;
      }

      if (code === 0x7f || code === 0x08){
        if (this.lineBuf.length>0){ this.lineBuf = this.lineBuf.slice(0,-1); this.xterm.write('\b \b'); }
        continue;
      }

      if (code === 0x03){ // Ctrl+C
        this.xterm.write('^C\r\n');
        try{
          await this._fetchJSON('?action=term-interrupt', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ sid:this.basicSid||'' })
          });
        }catch{}
        continue;
      }

      if (code < 32) continue;
      this.lineBuf += ch;
      this.xterm.write(ch);
    }
  },

  lastCols: 0,
  lastRows: 0,
  _requestFit(){
    try{ this.fit.fit(); } finally { this._maybeResizePost(); }
  },
  async _maybeResizePost(){
    if (!this.xterm) return;
    const cols = this.xterm.cols|0, rows = this.xterm.rows|0;
    if (cols===this.lastCols && rows===this.lastRows) return;
    this.lastCols = cols; this.lastRows = rows;

    if (this.mode==='tmux' && this.active){
      await this._fetchJSON('?action=term2-resize', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ sid:this.active, cols, rows })
      }).catch(e=>this._log('resize failed', e));
    }
  },

  async newTab(){
    this.initOnce();
    if (this.mode!=='tmux'){
      this.xterm.writeln('\r\n[INFO] 複数タブは tmux が必要です。');
      return;
    }
    try{
      const body = new FormData();
      body.append('cols', String(this.xterm.cols||120));
      body.append('rows', String(this.xterm.rows||30));
      const j = await this._fetchJSONForm('?action=term2-open', body);
      if (j?.ok){
        await this._refreshTmuxTabs();
        this.active = j.sid;
        this.lastScreenB64 = '';
        this._showBannerOnceFor(j.sid);
        this._renderTabs();
        this._startPollingTmux();
        this._maybeResizePost();
      } else {
        this._err(j?.error||'open failed');
      }
    }catch(e){ this._err('open error: '+e.message); }
  }
};

window.term = term;
window.addEventListener('DOMContentLoaded', () => {
  try {
    term.initOnce();
    term.bindUI();
  } catch (e) { console.error(e); }
});

</script>

</body>
</html>
