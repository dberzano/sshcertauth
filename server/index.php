<?php

/** index.php -- by Dario Berzano <dario.berzano@cern.ch>
 *
 *  Part of sshcertauth -- https://github.com/dberzano/sshcertauth
 *
 *  From an input certificate, passed to this script by means of environment
 *  variables set by the web server, it extracts the public key and converts it
 *  to the SSH pubkey format.
 *
 *  The key is subsequently added to a list of authorized keys.
 *
 *  The Unix username corresponding to the key is obtained by different methods
 *  (e.g., LDAP or round-robin mapping to a pool account).
 *
 *  Note that only RSA keys are supported: other key formats generate an error.
 *
 *  Key extraction is performed by OpenSSL, so it must be enabled at build time
 *  in your PHP version -- you can check it with phpinfo().
 *
 *  Key conversion is performed by a builtin phpseclib, distributed along with
 *  this code: phpseclib is covered by MIT license, see [1] for more
 *  information.
 *
 *  TODO: XML/JSON/RPC output (choose one...)
 *
 *  REQ: php5.2 (php53), php53-ldap, short_tags on
 *
 *  [1] http://phpseclib.sourceforge.net/
 */

/** Includes, definitions, global variables...
 */

// Include phpseclib and configuration
set_include_path( get_include_path() . PATH_SEPARATOR . 
  dirname($_SERVER['SCRIPT_FILENAME']) . '/phpseclib0.2.2' );
require_once 'Crypt/RSA.php';
require_once 'conf.php';

// Include module to retrieve user from client certificate's subject
require_once 'plugins/user/' . $pluginUser . '.php';

// When exporting to SSH key, do not append any text comment at the end
define('CRYPT_RSA_COMMENT', '');

// Defines for output types
define('AUTH_OUT_XML',  0);
define('AUTH_OUT_HTML', 1);
define('AUTH_OUT_TXT',  2);

// Date and time default format: e.g., 'Dec 11 2011 15:27:35 +0000' -- note that
// timezone is extremely important!
define('AUTH_DATETIME_FORMAT', 'M d Y H:i:s O');

// Temporarily set server name
$serverFqdn = $_SERVER['SERVER_NAME'];

// When auth succeeds, $authValid becomes true
$authValid = false;

// Version
$authVer = '0.2';

// Error messages are an array, empty at start
$errMsg = array();

/** Checks for required components, for now: OpenSSL in PHP >= 5.2 and LDAP.
 *  Returns true on success, false on failure. The only argument is an array of
 *  strings representing errors, passed by reference: each error is appended to
 *  that string.
 */
function authCheckReqs(&$reqErrMsg) {

  $nErrMsg = count($reqErrMsg);

  if (!isset($_SERVER['HTTPS']) || ($_SERVER['HTTPS'] != 'on')) {
    $reqErrMsg[] = "HTTPS mode is required\n";
  }

  if ((!isset($_SERVER['SSL_CLIENT_S_DN'])) ||
      (!isset($_SERVER['SSL_CLIENT_CERT']))) {
    $reqErrMsg[] = "Extended SSL variables " .
      "(SSLOptions +StdEnvVars +ExportCertData in apache2) must be enabled\n";
  }

  if (!function_exists('openssl_pkey_get_details')) {
    $reqErrMsg[] = "At least PHP 5.2 with OpenSSL enabled is required\n";
  }

  if (!function_exists('ldap_connect')) {
    $reqErrMsg[] = "LDAP support for PHP must be enabled\n";
  }

  if (!class_exists('SimpleXMLElement')) {
    $reqErrMsg[] = "SimpleXML for PHP must be enabled\n";
  }

  if (count($reqErrMsg) > $nErrMsg) return false;
  return true;
}

/**
 */
function authSetPubKey(&$pemCert, $userName, $tokenValiditySecs, $sshKeyDir,
  &$validUntilStr, &$extErrMsg) {

  // Checks if the key is in the correct format (only RSA supported)
  $pubkeyRes = openssl_pkey_get_public($pemCert);

  if ($pubkeyRes === false) {
    $extErrMsg[] = 'Can\'t extract pubkey from the certificate';
    return false;
  }

  $pubkeyDetails = openssl_pkey_get_details($pubkeyRes);

  if ($pubkeyDetails['type'] != OPENSSL_KEYTYPE_RSA) {
    $extErrMsg[] = 'Public key is not a RSA key';
    return false;
  }

  // The sole public key
  $pubkeyPkcs1Str = $pubkeyDetails['key'];

  // Load the public key: Crypt_RSA does not make any difference between public
  // and private
  $rsa = new Crypt_RSA();

  if ($rsa->loadKey($pubkeyPkcs1Str,
    CRYPT_RSA_PUBLIC_FORMAT_PKCS1) === false) {
    $extErrMsg[] = 'Public key is not a RSA key (phpseclib error)';
    return false;
  }

  // Trick to avoid double-parsing: Crypto_RSA thinks the loaded key is private,
  // so instead of invoking $rsa->setPublicKey(), we just make the
  // publicExponent equal to the current one
  $rsa->publicExponent = $rsa->exponent;

  // Convert the key to SSH
  $pubkeySshStr = $rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_OPENSSH);

  // Set expiration date: output is a string, timezone is UTC
  $validUntilTs = time() + $tokenValiditySecs;
  $validUntilStr = date(AUTH_DATETIME_FORMAT, $validUntilTs);

  // Expiration date, formatted, is appended as a comment to the key
  $pubkeySshStr .= ' Valid until: ' . $validUntilStr;

  // Key is sent 
  $ph = @proc_open(
    dirname($_SERVER['SCRIPT_FILENAME']) .
      "/keys_keeper.sh addkey --user '$userName' --keydir '$sshKeyDir'",
    array(
      0 => array('pipe', 'r'),
      1 => array('pipe', 'w'),
      2 => array('pipe', 'w')
    ),
    $pipes);

  if ($ph) {

    // The script expects the key on stdin
    fwrite($pipes[0], $pubkeySshStr);
    fclose($pipes[0]);

    // Errors from stderr
    while ($e = fread($pipes[2], 300)) {
      $extErrMsg[] = "Key stager: $e";
    }
    fclose($pipes[2]);

    if (proc_close($ph) == 0) return true;
  }

  // Error condition
  return false;
}

/** Get AliEn username from LDAP. See documentation here[1].
 *
 *  [1] http://php.net/manual/en/function.ldap-search.php
 */
/*function authGetUser(&$userName, &$maxValiditySecs) {

  $userName = 'testuser';
  $maxValiditySecs = 3600;
  return true;

  $lh = ldap_connect("aliendb06a.cern.ch", 8389);
  if (!$lh) return null;

  $lr = @ldap_search($lh, "ou=People,o=alice,dc=cern,dc=ch",
    "subject=" . $_SERVER["SSL_CLIENT_S_DN"], array("uid"));
  if (!$lr) return null;

  $li = ldap_get_entries($lh, $lr);
  if ($li["count"] != 1) return null;

  if (isset($li[0]["uid"])) {
    $user = $li[0]["uid"][0];
    return $user;
  }

  return null;
}*/

/** Entry point.
 */

// Choose output type (default: HTML)
if (isset($_GET['o'])) {
  switch ($_GET['o']) {
    case 'xml': $outputType = AUTH_OUT_XML; break;
    case 'txt': $outputType = AUTH_OUT_TXT; break;
    default: case 'html': $outputType = AUTH_OUT_HTML; break;
  }
}
else $outputType = AUTH_OUT_HTML;

if (authCheckReqs($errMsg) === true) {

  // Get server name from the certificate, and set client subject
  $serverFqdn = $_SERVER['SSL_SERVER_S_DN_CN'];
  $clientSubject = $_SERVER['SSL_CLIENT_S_DN'];

  if (!authGetUser($clientSubject, $userName, $validitySecs, $errMsg)) {
    $errMsg[] = "Can't get user from $pluginUser plugin";
  }
  else {

    // Argument is the PEM certificate (containing a RSA pubkey)
    if (authSetPubKey($_SERVER['SSL_CLIENT_CERT'], $userName, $validitySecs,
          $sshKeyDir, $validUntilStr, $errMsg)) {
      $authValid = true;
    }

  }

}

?>
<?php if ($outputType == AUTH_OUT_XML) :

$outXml = new SimpleXMLElement('<sshauth></sshauth>');
$outXml->addAttribute('version', $authVer);

// Error messages, if any
if (count($errMsg) > 0) {
  $errorsXml = $outXml->addChild('errors');
  $errorsXml->addAttribute('length', count($errMsg));
  foreach ($errMsg as $e) {
    $errXml = $errorsXml->addChild('errmsg', $e);
  }
}

// Server data
$serverXml = $outXml->addChild('server');
if (isset($serverFqdn)) $serverXml->addChild('name', $serverFqdn);
if (isset($sshPort)) $serverXml->addChild('port', $sshPort);

// Authentication data
$authXml = $outXml->addChild('auth');
if (isset($userName)) $authXml->addChild('user', $userName);
if (isset($validUntilStr)) $authXml->addChild('expires', $validUntilStr);
$authXml->addChild('valid', ($authValid ? 'true' : 'false'));

// Output XML
header('Content-type: text/xml');
echo $outXml->asXML();
?>
<? elseif ($outputType == AUTH_OUT_TXT) : ?>
<?php

// Text-only output is very minimal
header('Content-type: text/plain');
echo "$userName@$serverFqdn:$sshPort"

?>
<? elseif ($outputType == AUTH_OUT_HTML) : ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"
  "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en" dir="ltr">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Authentication to <?= $serverFqdn ?></title>

<style type="text/css">

body {
  font-family: Arial, helvetica, sans-serif;
  font-size: 11pt;
  color: black;
  background-color: white;
}

.imp {
  font-weight: bold;
  color: #565678;
}

.err {
  color: red;
  background-color: #ffdddd;
  padding: 5px;
  border: 2px dashed red;
  font-weight: bold;
}

.err ul {
  margin: 0px;
}

.cod {
  color: #121212;
  background-color: #dadada;
  padding: 5px;
  border: 1px dashed #121212;
  font-family: Monaco, Courier New, Lucida Console, monospace;
  margin-left: 20px;
}

</style>

</head>

<body>

<?php if (isset($serverFqdn) && isset($clientSubject)) : ?>
<h1>Authentication to <?= $serverFqdn ?></h1>

<p>You have been identified as:
  <span class="imp"><?php echo $clientSubject ?></span></p>
<?php endif ?>

<?php if (count($errMsg) > 0) : ?>

<div class="err"><ul><?php
foreach ($errMsg as $e) echo "<li>$e</li>\n"; ?></ul></div>

<?php else : ?>

<p>User information:</p>

<ul>
  <li>Your username: <span class="imp"><?php echo $userName ?></span></li>
  <li>Your authentication will remain valid until:
    <span class="imp"><?= $validUntilStr ?></span></li>
</ul>

<p>You can now login to <?= $serverFqdn ?> with your private key with the
following command:</p>

<p><span class="cod">ssh -p <?= $sshPort ?> -i ~/.globus/userkey.pem
  <?= $userName ?>@<?= $serverFqdn ?></span></p>

<p>No password will be asked.</p>

<?php endif ?>

</body>

</html>
<?php endif ?>
