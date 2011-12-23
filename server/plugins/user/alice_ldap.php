<?php

/** alice_ldap.php -- by Dario Berzano <dario.berzano@cern.ch>
 *
 *  Part of sshcertauth -- https://github.com/dberzano/sshcertauth
 *
 *  ALICE LDAP module for sshcertauth: it contains only a authGetUser() function
 *  returning true on success, false if user cannot be authenticated, and taking
 *  as arguments the subject, the variable where to store the username (by ref),
 *  and the validity in seconds (by ref). Last argument is the global array of
 *  errors, passed by reference: any error should be appended there as a string.
 */

function authGetUser($certSubject, &$userName, &$validitySecs, &$errMsg) {

  $lh = ldap_connect('aliendb06a.cern.ch', 8389);
  if (!$lh) {
    $errMsg[] = 'Can\'t contact AliEn LDAP';
    return false;
  }

  $lr = @ldap_search($lh, 'ou=People,o=alice,dc=cern,dc=ch',
    'subject=' . $certSubject, array('uid'));
  if (!$lr) {
    $errMsg[] = 'LDAP search failed';
    ldap_close($lh);
    return false;
  }

  $li = ldap_get_entries($lh, $lr);
  if ($li['count'] != 1) {
    $errMsg[] = 'User not found in ALICE LDAP';
    ldap_close($lh);
    return false;
  }

  if (isset($li[0]['uid'])) {
    $userName = $li[0]['uid'][0];
    $validitySecs = 43200;  // 12h
    return true;
  }

  $errMsg[] = 'Can\'t find username in LDAP response';
  return false;

}

?>
