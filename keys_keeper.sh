#!/bin/bash

#
# keys_keeper.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# Part of sshcertauth.
#
# The keys keeper is the only part of sshcertauth meant to be run as root. It
# implements two working modes:
#
# keys_keeper.sh [addkey|expiry] [-k|--keydir <dir>] [-u|--user <user>] \
#   [-v|--verbose]
#
#  - addkey : Adds the given key (on stdin) to the current user's authorized
#             keys. User is passed with the --user argument. If the current key
#             is already present, its expiration date is updated. If not, the
#             key is appended.
#
#  - expiry : Scans the keys directory in order to remove expired keys. Those
#             keys are removed from the files, and if a file has no more keys
#             inside, it is removed. Keys without a valid expiration date are
#             left intact.
#
# It is worth noting that this script supports multiple keys per file. If it is
# not run as root, it auto-invokes sudo on itself, so for non-interactive usage
# /etc/sudoers must be properly configured.
#
# The variable --keydir is mandatory, but if not given an autodetect from the
# PHP configuration file (conf.php in the same folder) is performed. For this
# to work, the command-line interface (CLI) for PHP must be installed.
#
# Everything is logged by the system logger, i.e.: /var/log/messages. If verbose
# option is enabled, messages are printed on stderr too.
#
# An exit state of zero means success; nonzero means some kind of failure.
#

#
# Preamble: run as root. We must have proper configuration in /etc/sudoers.
#

if [ "$USER" != 'root' ]; then
  exec sudo "$0" "$@"
fi

#
# Global variables
#

# Directory containing SSH keys, one file (with multiple keys) for each user
export SshKeyDir

# Maximum number of seconds to wait for a lock
export LockLimit=5

# Verbosity on stdout and on /var/log/messages
export VerboseScreen=0
export VerboseLogger=1
export LoggerTag='keys_keeper'

#
# Functions
#

# Adds a key (from stdin) in the list of authorized ones. Multiple keys per file
# are supported.
function AddKey() {

  # Username
  local UserName="$1"

  # Key is passed on stdin
  local PubKey=$(cat)

  # Full path to key
  local FullKeyFilePath="$SshKeyDir/$UserName"

  # Check if this key is already in the list of authorized ones for this
  # username (useful if using the same Unix username for multiple users, as
  # "pool account")
  local PubKeyCore=`echo "$PubKey" | awk '{ print $2 }'`

  # Lock
  if ! LockWait $UserName; then
    prn "Cannot obtain mutex on authorized keys file, exiting"
    exit 1
  fi

  # Is key present?
  local Renew=0
  grep -c "$PubKeyCore" "$FullKeyFilePath" > /dev/null 2>&1
  if [ $? == 0 ]; then

    # Key is already present: remove it to renew it
    grep -v "$PubKeyCore" "$FullKeyFilePath" > "$FullKeyFilePath".0
    rm -f "$FullKeyFilePath"
    mv "$FullKeyFilePath".0 "$FullKeyFilePath"
    Renew=1

  fi

  # Key is not present: append it (take into account write errors)
  echo "$PubKey" >> "$FullKeyFilePath"
  if [ $? == 0 ]; then
    if [ $Renew == 1 ]; then
      prn "$UserName: this key already exists, renewing it"
    else
      prn "$UserName: authorizing new key"
    fi
  else
    prn "$UserName: can't authorize key, write error!"
    exit 1
  fi

  # No error at this point: we can unlock
  exit 0

}

# Here we lock a keyfile: let's create a lock directory for obvious safety
# reasons. The lock/wait operation stays in the mkdir command, which is
# atomic (on most local filesystems): if the creation of the lock directory
# fails, there already is a lock; we try again LockLimit times then we give up,
# returning 1
function LockWait() {

  local LockDir="$SshKeyDir/$1".lock
  local LockSuccess=1
  local LockCount=0

  while ! mkdir "$LockDir" 2> /dev/null; do
    if [ $LockCount == $LockLimit ]; then
      LockSuccess=0
      break
    fi
    sleep 1
    let LockCount++
  done

  # At this point we've given up waiting
  [ $LockSuccess == 0 ] && return 1

  # Remove lock in case of exit/abort/etc. (only sigkill is uninterruptible)
  trap "Unlock $1" 0

  return 0
}

# Reads a variable from the PHP configuration file of sshcertauth. It requires
# php-cli to work properly. Variable content is outputted on
function ConfPhp() {
  local FullDir=$(dirname $0)
  php <<EOF
<?php
@require '$FullDir/conf.php';
if (isset(\$$1)) { echo "\$$1\n"; exit(0); }
exit(1);
?>
EOF
}

# Print function with a custom prefix: it also prints on /var/log/messages
function prn() {
  [ $VerboseScreen == 1 ] && echo "$@" >&2
  [ $VerboseLogger == 1 ] && logger -t "$LoggerTag" "$@"
}

# Remove expired keys from the SSH authorized keys directory. Multiple keys per
# file are supported. Only keys with a 'Valid until:' comment field are
# considered. When key files are empty, they are completely removed.
function Expiry() {

  local ExpDateIdx
  local ExpDateStr
  local ExpDateTs
  local Now=`date +%s`
  local CountKeys

  # Variables used for report
  local CountScannedKeys=0
  local CountValidKeys=0
  local CountSkippedKeys=0
  local CountScannedFiles=0
  local CountDeletedFiles=0

  # Change wd
  cd "$SshKeyDir"

  # Print starting banner
  prn "Scan of SSH key directory $SshKeyDir started"

  # Loop over all keys (only files)
  for KeyFile in *; do

    [ ! -f $KeyFile ] && continue
    let CountScannedFiles++  # report

    if ! LockWait $KeyFile; then
      prn "$KeyFile: can't obtain mutex, skipping file!"
      continue
    fi

    local TmpKeyFile="$KeyFile".0
    echo -n '' > $TmpKeyFile

    CountKeys=0  # valid keys

    local KeyFileReadDone=0
    while [ $KeyFileReadDone == 0 ] ; do

      # Works also if no newline before EOF
      read Key || KeyFileReadDone=1
      let CountScannedKeys++  # report

      # Is the "Valid until:" comment present inside the key? ExpDateIdx is set
      # to 0 if unpresent
      ExpDateIdx=`echo "$Key" | awk '{ print index($0, "Valid until:") }'`
      let ExpDateIdx+=0  # convert to an integer (indirect check if is a num)

      # Keep the key or not?
      local KeepKey=0

      # By default date format is invalid/not present
      local ExpDateInvalid=1

      if [ "$ExpDateIdx" -gt 0 ]; then

        let ExpDateIdx+=11
        ExpDateStr="${Key:$ExpDateIdx}"
        ExpTs=`date -d "$ExpDateStr" +%s 2> /dev/null`
        [ $? == 0 ] && ExpDateInvalid=0 || ExpDateInvalid=1

        if [ $ExpDateInvalid == 0 ] && [ $ExpTs -gt $Now ]; then
          # Date format is valid and key is not expired yet: keep it
          KeepKey=1
          let CountValidKeys++
          prn "$KeyFile: kept a valid key"
        fi

      else
        # Date format is invalid: keep the key
        KeepKey=1
        let CountSkippedKeys++
        prn "$KeyFile: skipped a key without expiration date"
      fi

      # Are we keeping the key?
      if [ $KeepKey == 1 ]; then
        let CountKeys++
        echo "$Key" >> $TmpKeyFile
      else
        prn "$KeyFile: deleted an expired key"
      fi

    done < $KeyFile

    if [ $CountKeys == 0 ]; then
      # No more valid keys: remove file
      rm -f $KeyFile $TmpKeyFile
      prn "$KeyFile: no valid keys, file removed"
      let CountDeletedFiles++
    else
      # Substitute file with temporary file containing only valid keys.
      # Symbolic links are preserved: original file is modified
      cat $TmpKeyFile > $KeyFile
      rm -f $TmpKeyFile
    fi

    Unlock $KeyFile

  done

  # Revert to old wd
  cd - > /dev/null

  # Print report
  local CountDeletedKeys
  local CountKeptFiles
  let CountDeletedKeys=CountScannedKeys-CountValidKeys-CountSkippedKeys
  let CountKeptFiles=CountScannedFiles-CountDeletedFiles

  prn "Keys scanned: $CountScannedKeys ($CountValidKeys valid +" \
      "$CountSkippedKeys skipped + $CountDeletedKeys deleted)"
  prn "Files scanned: $CountScannedFiles ($CountKeptFiles kept +" \
      "$CountDeletedFiles deleted)"
  prn 'Scan finished'

}

# Removes the lockdir and unsets EXIT traps. It takes the username as its only
# argument
function Unlock() {
  rmdir "$SshKeyDir/$1".lock 2> /dev/null
  trap '' 0  # unset EXIT traps
}

# The main function
function Main() {

  local ProgName
  local Args
  local UserName

  ProgName=`basename "$0"`
  Args=$(getopt -ok:u:v --long keydir:,user:,verbose -n"$ProgName" -- "$@") \
    || exit 1

  eval set -- "$Args"

  Count=0

  while [ "$1" != '--' ]; do
  
    case "$1" in

      -u|--user)
        UserName="$2"
        shift 2
      ;;

      -k|--keydir)
        SshKeyDir="$2"
        shift 2
      ;;

      -v|--verbose)
        VerboseScreen=1
        shift
      ;;

      *)
        echo "Unknown: $1"
        shift
      ;;

    esac

  done

  shift # get rid of '--'

  # If SshKeyDir is not given, read it from the configuration file in PHP
  [ "$SshKeyDir" == '' ] && SshKeyDir=`ConfPhp 'sshKeyDir'`

  # Integrity checks on dir variable
  if [ "${SshKeyDir:0:1}" != '/' ] || [ ${#SshKeyDir} -lt 4 ]; then
    prn "Invalid SSH keydir variable: $SshKeyDir, exiting"
    exit 1
  fi

  # Does the keys directory exist?
  if [ ! -d "$SshKeyDir" ]; then
    prn "Can't access key directory: $SshKeyDir, exiting"
    exit 1
  fi

  # Working mode
  if [ "$1" == 'expiry' ]; then
    LoggerTag="${LoggerTag}[expiry]"
    Expiry
  elif [ "$1" == 'addkey' ]; then
    LoggerTag="${LoggerTag}[addkey]"
    if [ "$UserName" == '' ]; then
      prn "Mandatory username not set, exiting"
      exit 1
    fi
    AddKey "$UserName"
  else
    prn "No action given (try \"expiry\" or \"addkey\"), exiting"
    exit 1
  fi

}

#
# Entry point
#

Main "$@"
