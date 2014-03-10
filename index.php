<?php

/**
 * index.php -- by Dario Berzano <dario.berzano@cern.ch>
 *
 * Part of sshcertauth -- https://github.com/dberzano/sshcertauth
 *
 * From an input certificate, passed to this script by means of environment
 * variables set by the web server, it extracts the public key and converts it
 * to the SSH pubkey format.
 *
 * The key is subsequently added to a list of authorized keys.
 *
 * The Unix username corresponding to the key is obtained by different methods
 * (e.g., LDAP or round-robin mapping to a pool account).
 *
 * Note that only RSA keys are supported: other key formats generate an error.
 *
 * Key extraction is performed by OpenSSL, so it must be enabled at build time
 * in your PHP version -- you can check it with phpinfo().
 */

//
// Redirect every request to this script
//

$RedirTo = dirname($_SERVER['SCRIPT_NAME']) . '/';
if ($_SERVER['QUERY_STRING'] != '') {
  $RedirTo .= '?' . $_SERVER['QUERY_STRING'];
}
if ($_SERVER['REQUEST_URI'] != $RedirTo) {
  header("Location: $RedirTo", true, 302);
  die();
}

//
// Includes, definitions, global variables...
//

// Defines for output types
define('AUTH_OUT_XML',  0);
define('AUTH_OUT_HTML', 1);
define('AUTH_OUT_TXT',  2);

// Parse configuration
$confOk = false;
$confFiles = array('/etc/sshcertauth/conf.php', './conf.php');
foreach ($confFiles as $confFile) {
  if (is_readable($confFile)) {
    require_once $confFile;
    $confOk = true;
    break;
  }
}
if ($confOk) {
  // Include module to retrieve user from client certificate's subject
  $pluginFiles = array("/usr/lib/sshcertauth/plugins/user/${pluginUser}.php", "./plugins/user/${pluginUser}.php");
  foreach ($pluginFiles as $pluginFile) {
    if (is_readable($pluginFile)) {
      require_once $pluginFile;
      break;
    }
  }
}
else {
  // Define a dummy function to prevent a fatal error
  function authGetUser() {}
  $userName = '';
  $validitySecs = 0;
  $pluginUser = '';
  $opensslBin = 'openssl';
}

// Date and time default format: e.g., 'Dec 11 2011 15:27:35 +0000' -- note that
// timezone is extremely important!
define('AUTH_DATETIME_FORMAT', 'M d Y H:i:s O');

// Temporarily set server name
$serverFqdn = $_SERVER['SERVER_NAME'];

// When auth succeeds, $authValid becomes true
$authValid = false;

// Version
$authVer = '0.9.0';

// Error messages are an array, empty at start
$errMsg = array();

//
// Functions
//

//______________________________________________________________________________
function authCheckReqs(&$reqErrMsg) {

  // Checks for required components, for now: OpenSSL in PHP >= 5.2 and LDAP.
  // Returns true on success, false on failure. The only argument is an array of
  // strings representing errors, passed by reference: each error is appended to
  // that string.

  $nErrMsg = count($reqErrMsg);

  if (!isset($_SERVER['HTTPS']) || ($_SERVER['HTTPS'] != 'on')) {
    $reqErrMsg[] = 'HTTPS mode is required';
  }

  if ((!isset($_SERVER['SSL_CLIENT_S_DN'])) ||
      (!isset($_SERVER['SSL_CLIENT_CERT']))) {
    $reqErrMsg[] = 'Extended SSL variables ' .
      '(SSLOptions +StdEnvVars +ExportCertData in apache2) must be enabled';
  }

  if (!function_exists('openssl_pkey_get_public')) {
    $reqErrMsg[] = 'PHP with OpenSSL support is required';
  }

  if (!function_exists('ldap_connect')) {
    $reqErrMsg[] = 'PHP with LDAP support is required';
  }

  if (!class_exists('SimpleXMLElement')) {
    $reqErrMsg[] = 'PHP with SimpleXML support is required';
  }

  return !(count($reqErrMsg) > $nErrMsg);
}

//______________________________________________________________________________
function authAllowPubkey(&$pubkeySsh, $userName, $sshKeyDir, &$extErrMsg) {

  // Places the given public key in SSH format in the authorized keys file using
  // proper external commands. In order for the external scripts to work, the
  // sudoers file should be configured properly as described on the manual.
  // Returns true on success, false on failure. In case of failure, error
  // messages are appended to the given array of error messages

  $ph = @proc_open(
    dirname($_SERVER['SCRIPT_FILENAME']) .
      "/keys_keeper.sh addkey --user '$userName' --keydir '$sshKeyDir'",
    array(
      0 => array('pipe', 'r'),
      1 => array('pipe', 'w'),
      2 => array('pipe', 'w')
    ),
    $pipes
  );

  if ($ph) {

    // Script expects the key on stdin
    fwrite($pipes[0], $pubkeySsh);
    fclose($pipes[0]);

    // Errors from stderr
    $stderrStr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    if ($stderrStr != '') {
      $extErrMsg[] = "Key stager: $stderrStr";
    }

    if (proc_close($ph) == 0) return true;
  }

  return false;  // error
}

//______________________________________________________________________________
function authX509PemCertToSshRsaPubKey($in_cert, $pubkey_comment, $opensslBin,
  &$extErrMsg) {

  // Given a X.509 certificate in PEM format, it extracts the public key and
  // returns it as a one-line armored string converted to the SSH public key
  // format, as described in rfc4253. Returns false if an error occurs. OpenSSL
  // executable is used: path can be configured in conf.php

  $ph = @proc_open(
    "LANG=C '$opensslBin' x509 -noout -pubkey | " .
    "'$opensslBin' rsa -pubin -noout -text",
    array(
      0 => array('pipe', 'r'),
      1 => array('pipe', 'w'),
      2 => array('pipe', 'w')
    ),
    $pipes
  );

  if (!is_resource($ph)) {
    $extErrMsg[] = 'Cannot open I/O streams to/from openssl';
    return false;
  }

  // Silence stderr
  fclose($pipes[2]);

  // Send PEM certificate to the stream
  fwrite($pipes[0], $in_cert);
  fclose($pipes[0]);

  // Hexadecimal strings of exponent and modulus
  $n_str = '';
  $e_str = '';

  // Parse openssl output and get exponent and modulus
  $parse_n = false;
  while ($buf = fgets($pipes[1])) {
    if ($parse_n) {
      if (strstr($buf, 'Exponent')) {
        $m = array();
        preg_match("/\(0x([0-9A-Za-z]+)\)/", $buf, $m);
        $e_str = $m[1];
        if (strlen($e_str) % 2) $e_str = '0' . $e_str;
      }
      else {
        $n_str .= $buf;
      }
    }
    else if (strstr($buf, 'Modulus')) {
      $parse_n = true;
    }
  }

  fclose($pipes[1]);
  $rv = proc_close($ph);

  // Removes all garbage from modulus string (line returns, colons,...)
  $n_str = preg_replace("/[^0-9A-Za-z]/", "", $n_str);

  if (($rv != 0) || ($e_str == '') || ($n_str == '')) {
    $extErrMsg[] = 'There was a problem parsing the public key';
    return false;
  }

  // Final format will be [rfc4253]:
  //   string 'ssh-rsa'
  //   mpint e
  //   mpint n
  // Fields are prefixed with a 4-byte big-endian length. mpint are in
  // big-endian format as well.

  $raw_outkey =
    pack('N', 7)                . 'ssh-rsa' .
    pack('N', strlen($e_str)/2) . pack('H*', $e_str) .
    pack('N', strlen($n_str)/2) . pack('H*', $n_str);

  // Returns full SSH key, with comment appended
  if ($pubkey_comment != '') {
    $pubkey_comment = ' ' . $pubkey_comment;
  }

  return 'ssh-rsa ' . base64_encode($raw_outkey) . $pubkey_comment;
}

//
// Entry point: no output should be produced before this point
//

// Choose output type (defaults to HTML)
if (isset($_GET['o'])) {
  switch ($_GET['o']) {
    case 'xml':
      $outputType = AUTH_OUT_XML;
    break;
    case 'txt':
      $outputType = AUTH_OUT_TXT;
    break;
    default: case 'html':
      $outputType = AUTH_OUT_HTML;
    break;
  }
}
else $outputType = AUTH_OUT_HTML;

// Get server name from the certificate, and set client subject
$serverFqdn = $_SERVER['SSL_SERVER_S_DN_CN'];
$clientSubject = $_SERVER['SSL_CLIENT_S_DN'];

if ($confOk === false) {
  $errMsg[] = 'Please write your configuration first!';
}
else if (authCheckReqs($errMsg) === true) {
  if (!authGetUser($clientSubject, $userName, $validitySecs, $errMsg)) {
    $errMsg[] = "Can't get user from $pluginUser plugin";
  }
  else {

    // Set expiration date: output is a string, timezone is UTC
    if (($validitySecs > $maxValiditySecs) || ($validitySecs <= 0)) {
      $validitySecs = $maxValiditySecs;  // cap validity
    }
    $validUntilTs = time() + $validitySecs;
    $validUntilStr = date(AUTH_DATETIME_FORMAT, $validUntilTs);

    // Expiration date, formatted, is appended as a comment to the key
    $pubkeySshComment = "Valid until: $validUntilStr";

    $pubkeySsh = authX509PemCertToSshRsaPubKey($_SERVER['SSL_CLIENT_CERT'],
      $pubkeySshComment, $opensslBin, $errMsg);

    if ($pubkeySsh === false) {
      $errMsg[] = "Cannot extract pubkey in SSH format from PEM certificate";
    }
    else {
      if (authAllowPubkey($pubkeySsh, $userName, $sshKeyDir, $extErrMsg)) {
        $authValid = true;
      }
      else {
        $errMsg[] = 'Cannot allow public key';
      }
    }

  }
}

//
// Output in XML
//

if ($outputType == AUTH_OUT_XML) :

$outXml = new SimpleXMLElement('<sshcertauth></sshcertauth>');
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

//
// Output in Plain Text
//

elseif ($outputType == AUTH_OUT_TXT) :

// Text-only output is very minimal
header('Content-type: text/plain');
echo "$userName@$serverFqdn:$sshPort";

//
// Output in HTML
//

elseif ($outputType == AUTH_OUT_HTML) : ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"
  "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en" dir="ltr">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Authentication to <?php echo $serverFqdn ?></title>

<link href='https://fonts.googleapis.com/css?family=Open+Sans:400,600'
rel='stylesheet' type='text/css'/>
<style type="text/css">

body {
  font-family: Open Sans, Arial, helvetica, sans-serif;
  font-weight: 400;
  font-size: 11pt;
  color: black;
  background-color: white;
}

b, strong {
  font-weight: 600;
}

h1, h2, h3, h4, h5, h6 {
  font-family: Open Sans, Arial, helvetica, sans-serif;
  font-weight: 400;
  color: #0489B7;
}

p {
  margin-top: 20px;
  margin-bottom:20px;
}

.imp {
  font-weight: bold;
  color: #0489B7;
}

.err {
  -moz-box-shadow: inset 0 0 9px red;
  -webkit-box-shadow: inset 0 0 9px red;
  box-shadow: inner 0 0 9px red;
  background-color: #ffdddd;
  padding: 10px;
  border-radius: 10px;
  color: red;
}

.err ul {
  margin: 0px;
}

.cod {
  -moz-box-shadow: inset 0 0 9px #204a87;
  -webkit-box-shadow: inset 0 0 9px #204a87;
  box-shadow: inner 0 0 9px #204a87;
  background-color: rgb(228,240,245);
  padding: 10px;
  border-radius: 10px;
  color: #204a87;
  font-family: monospace;
  margin-left: 20px;
  white-space: nowrap;
}

.ver, .ver a {
  color: #c0c0c0;
  text-decoration: none;
}

.ver a:hover {
  text-decoration: underline;
}

.ver {
  font-size: 80%;
  font-style: italic;
}

</style>

</head>

<body>

<?php if (isset($serverFqdn) && isset($clientSubject)) : ?>
<h1>Authentication to <?php echo $serverFqdn ?></h1>

<p>You have been identified as:</p>

<p><span class="cod"><?php echo $clientSubject ?></span></p>

<?php endif ?>

<?php if (count($errMsg) > 0) : ?>

<div class="err"><ul><?php
foreach ($errMsg as $e) echo "<li>$e</li>\n"; ?></ul></div>

<?php else : ?>

<p>User information:</p>

<ul>
  <li>Your username: <span class="imp"><?php echo $userName ?></span></li>
  <li>Your authentication will remain valid until:
    <span class="imp"><?php echo $validUntilStr ?></span></li>
</ul>

<p>You can now login to <span class="imp"><?php echo $serverFqdn ?></span> with
your private key<?php if (isset($suggestedCmd) && ($suggestedCmd != '')) : ?> using the following command:</p>

<p><span class="cod"><?php

// Prints a suggested command to access the server: it can be customized
$suggestedCmd = str_replace('<PORT>', $port, $suggestedCmd);
$suggestedCmd = str_replace('<USER>', $userName, $suggestedCmd);
$suggestedCmd = str_replace('<HOST>', $serverFqdn, $suggestedCmd);

print htmlspecialchars($suggestedCmd);

?></span></p>

<?php else : ?>.</p><?php endif ?>

<p>No password will be asked.</p>

<p class="ver"><a href="https://github.com/dberzano/sshcertauth">sshcertauth
v<?php echo $authVer ?></a></p>

<?php endif ?>

</body>

</html>
<?php endif ?>
