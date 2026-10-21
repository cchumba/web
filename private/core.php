<?php
declare(strict_types=1);
ini_set('display_errors','0');
date_default_timezone_set('America/Santiago');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
header("Content-Security-Policy: default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
header('Cache-Control: no-store');
$configFile=__DIR__.'/config.php';
if(!is_file($configFile)){http_response_code(503);exit('Configure private/config.php según INSTALACION.md para iniciar.');}
$config=require $configFile;
if(($config['https_only']??true) && (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS']==='off')){http_response_code(403);exit('Abra este sitio mediante HTTPS. Active AutoSSL en cPanel.');}
session_set_cookie_params(['httponly'=>true,'secure'=>$config['https_only']??true,'samesite'=>'Lax']);
ini_set('session.use_strict_mode','1');session_start();
$_SESSION['csrf']??=bin2hex(random_bytes(32));
function e($v):string{return htmlspecialchars((string)$v,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function db():PDO{static $db;global $config;if(!$db){$db=new PDO('mysql:host='.$config['host'].';dbname='.$config['database'].';charset=utf8mb4',$config['username'],$config['password'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);}return $db;}
function q(string $sql,array $args=[]):PDOStatement{$s=db()->prepare($sql);$s->execute($args);return $s;}
function csrf():void{echo '<input type="hidden" name="csrf" value="'.e($_SESSION['csrf']).'">';}
function checkcsrf():void{if(!hash_equals($_SESSION['csrf'],(string)($_POST['csrf']??''))){throw new RuntimeException('La sesión del formulario venció. Recarga la página.');}}
function field(string $key,int $max=255,bool $required=true):string{$s=trim((string)($_POST[$key]??''));if(($required&&$s==='')||strlen($s)>$max)throw new RuntimeException('Revisa el campo '.$key.'.');return $s;}
function go(string $p):never{header('Location: index.php?p='.$p);exit;}
function setting(string $key,string $default=''):string{$s=q('SELECT value FROM sc_settings WHERE name=?',[$key])->fetchColumn();return $s===false?$default:(string)$s;}
function me():?array{if(empty($_SESSION['uid']))return null;if(time()-($_SESSION['last']??0)>1800){unset($_SESSION['uid']);return null;}$_SESSION['last']=time();return q('SELECT id,email,role FROM sc_users WHERE id=? AND active=1',[$_SESSION['uid']])->fetch()?:null;}
function need(string $role=''):array{$u=me();if(!$u||($role!==''&&$u['role']!==$role)){http_response_code(403);exit('Acceso no autorizado.');}return $u;}
function throttle(string $scope,int $max):void{$key=hash('sha256',$scope.'|'.($_SERVER['REMOTE_ADDR']??'unknown').'|'.intdiv(time(),900));q('INSERT INTO sc_limits (bucket,hits,created_at) VALUES (?,1,NOW()) ON DUPLICATE KEY UPDATE hits=hits+1',[$key]);if((int)q('SELECT hits FROM sc_limits WHERE bucket=?',[$key])->fetchColumn()>$max)throw new RuntimeException('Demasiados intentos. Espera 15 minutos.');q('DELETE FROM sc_limits WHERE created_at < NOW() - INTERVAL 1 DAY');}
function audit(string $action,int $id=0):void{q('INSERT INTO sc_audit (user_id,action,target_id) VALUES (?,?,?)',[$_SESSION['uid']??null,$action,$id]);}
function picture():string{if(empty($_FILES['image']['name']))return ''; $f=$_FILES['image'];if($f['error']!==UPLOAD_ERR_OK||$f['size']>5*1024*1024)throw new RuntimeException('Imagen inválida o mayor a 5 MB.');$mime=(new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']);$ext=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'][$mime]??null;if(!$ext||!getimagesize($f['tmp_name']))throw new RuntimeException('Use JPG, PNG o WEBP.');$name='media/'.bin2hex(random_bytes(16)).'.'.$ext;if(!move_uploaded_file($f['tmp_name'],dirname(__DIR__).'/'.$name))throw new RuntimeException('No se pudo guardar la imagen.');return $name;}
set_exception_handler(function(Throwable $e){error_log('Condominio: '.$e->getMessage());http_response_code(500);echo 'No se pudo completar la operación. Revisa la configuración o contacta a la administración.';});
