<?php

/** conf.php -- by Dario Berzano <dario.berzano@cern.ch>
 *
 *  Part of sshcertauth -- https://github.com/dberzano/sshcertauth
 *
 *  Configuration settings for sshcertauth.
 */

// SSH port
$sshPort = 22;

// Authorized keys directory
$sshKeyDir = '/tmp/authorized_keys_test';

// Maximum token validity, in seconds
$maxValiditySecs = 3600;

// Plugin to retrieve the username based on the certificate subject: it is a PHP
// source file included from plugins/user directory -- specify it without the
// .php extension
$pluginUser = 'alice_ldap';

?>
