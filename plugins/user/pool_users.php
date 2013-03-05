<?php

/** generic_pool.php -- by Dario Berzano <dario.berzano@cern.ch>
 *
 *  Part of sshcertauth -- https://github.com/dberzano/sshcertauth
 *
 *  This authentication module, given a certificate subject, maps it to the
 *  first free pool account on the system. The system makes sure that a pool
 *  account is never assigned more than once 
 *
 *  Configuration variables:
 *   - $mapFile         : mapping database writable by the webserver's user
 *   - $mapValiditySecs : mapping validity, pruned after that many seconds
 *   - $mapUserFormat   : format string for user account name: must contain a
 *                        printf-like %u, substituted with a pool account ID
 *   - $mapIdLow        : lower boundary for pool ID
 *   - $mapIdHigh:      : upper boundary for pool ID
 *
 *  Pool users must exist on every node.
 */

function authGetUser($certSubject, &$userName, &$validitySecs, &$errMsg) {

  global $mapFile, $mapValiditySecs, $mapIdLow, $mapIdHi, $mapUserFormat;

  //
  // Check configuration variables
  //

  if (!isset($mapFile)) {
    $errMsg[] = 'Pool mapfile not specified';
    return false;
  }

  if (!isset($mapValiditySecs)) {
    $errMsg[] = 'Pool mapping validity not set';
    return false;
  }

  if (!isset($mapIdLow) || !isset($mapIdHi) || !isset($mapUserFormat)) {
    $errMsg[] = 'Users mapping variables not set';
    return false;
  }

  // Open it and parse it
  $fp = fopen($mapFile, 'r+');
  if (!$fp) {
    $errMsg[] = 'Cannot open X.509 mapfile';
    return false;
  }

  // Acquire shared lock - waits until lock is available
  if (!flock($fp, LOCK_EX)) {
    $errMsg[] = 'Cannot acquire exclusive lock on X.509 mapfile';
    fclose($fp);
    return false;
  }

  // Reads whole mappings in memory. In the meanwhile, cleanup entries outside
  // pool ID range and with "expired" timestamp, and look if we have a
  // previously assigned ID
  $curtime = time();  // seconds, and always in UTC
  $mappings = array();
  $idFound = -1;
  while ($buf = fgets($fp)) {
    if (preg_match('/^\s*"([^"]+)"\s+([0-9]+)\s+([0-9]+)\s*$/', $buf, $match)) {
      $id = intval($match[3]);
      if (($id < $mapIdLow) || ($id > $mapIdHi)) continue;  // invalid pool ID
      $ts = intval($match[2]);
      if (($curtime - $ts) > $mapValiditySecs) continue;  // mapping expired
      $map = array();
      $map['subj'] = $match[1];
      $map['ts'] = $ts;
      $mappings[$id] = $map;
      if ($certSubject == $map['subj']) $idFound = $id;
    }
  }

  // Do we have an ID? Might not succeed
  if ($idFound == -1) {
    for ($id=$mapIdLow; $id<=$mapIdHi; $id++) {
      if (!isset($mappings[$id])) {
        $idFound = $id;
        break;
      }
    }
  }

  // Check again: update existing, or create new one
  if ($idFound != -1) {
    $map['subj'] = $certSubject;
    $map['ts'] = $curtime;
    $mappings[$id] = $map;
  }

  // Writes everything back to the file
  ftruncate($fp, 0);
  rewind($fp);

  // We use this instead of foreach to sort results by pool ID
  for ($id=$mapIdLow; $id<=$mapIdHi; $id++) {
    if (!isset($mappings[$id])) continue;
    $map = $mappings[$id];
    fwrite($fp, "\"${map['subj']}\" ${map['ts']} $id\n");
  }

  //foreach ($mappings as $id => $map) {
  //  fwrite($fp, "\"${map['subj']}\" ${map['ts']} $id\n");
  //}

  // Cleanup
  flock($fp, LOCK_UN);
  fclose($fp);

  if ($idFound != -1) {
    $validitySecs = 0;  // don't decide: will be the maximum possible
    $userName = sprintf($mapUserFormat, $idFound);
    return true;
  }

  $errMsg[] = 'No pool accounts are available at this time';
  return false;
}

?>
