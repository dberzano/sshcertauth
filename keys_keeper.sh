#!/bin/bash

#
# keys_keeper.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# Part of sshcertauth.
#
# Some description is still pending.
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
  LockWait $UserName
  if [ $? != 0 ] ; then
    echo "Cannot obtain mutex on authorized keys file" >&2
    exit 1
  fi

  # Is key present?
  grep -c "$PubKeyCore" "$FullKeyFilePath" > /dev/null 2>&1
  if [ $? == 0 ]; then

    # Key is already present: remove it to renew it
    grep -v "$PubKeyCore" "$FullKeyFilePath" > "$FullKeyFilePath".0
    rm -f "$FullKeyFilePath"
    mv "$FullKeyFilePath".0 "$FullKeyFilePath"

  fi

  # Key is not present: append it (take into account write errors)
  echo "$PubKey" >> "$FullKeyFilePath"
  [ $? != 0 ] && exit 1

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

# Remove expired keys from the SSH authorized keys directory. Multiple keys per
# file are supported. Only keys with a 'Valid until:' comment field are
# considered. When key files are empty, they are completely removed.
function Expiry() {

  # Change wd
  cd "$SshKeyDir"

  # Loop over all keys (only files)
  for KeyFile in *; do

    [ ! -f $KeyFile ] && continue

    if LockWait $KeyFile ; then
      echo lock is successful
    fi

    echo '-->' $KeyFile

    Unlock $KeyFile

  done

  # Revert to old wd
  cd -

}

# Removes the lockdir and unsets EXIT traps. It takes the username as only
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
  Args=$(getopt -ok:u: --long keydir:,user: -n"$ProgName" -- "$@") || exit 1

  eval set -- "$Args"

  Count=0

  while [ "$1" != '--' ]; do
  
    #echo "Parsing arg: $1" >&2
    case "$1" in

      -u|--user)
        UserName="$2"
        shift 2
      ;;

      -k|--keydir)
        SshKeyDir="$2"
        shift 2
      ;;

      *)
        echo "Unknown: $1"
        shift
      ;;

    esac

    let Count++
    [ $Count == 10 ] && break

  done

  shift # get rid of '--'

  # Integrity checks on dir variable
  if [ "${SshKeyDir:0:1}" != '/' ] || [ ${#SshKeyDir} -lt 4 ]; then
    echo "Invalid SSH keydir variable: $SshKeyDir" >&2
    exit 1
  fi

  # Does the keys directory exist?
  if [ ! -d "$SshKeyDir" ]; then
    echo "Can't access key directory: $SshKeyDir" >&2
    exit 1
  fi

  # Working mode
  if [ "$1" == 'expiry' ]; then
    Expiry
  elif [ "$1" == 'addkey' ]; then
    if [ "$UserName" == '' ]; then
      echo "Mandatory username not set" >&2
      exit 1
    fi
    AddKey "$UserName"
  fi

}

#
# Entry point
#

Main "$@"
echo 'list of traps:' >&2
trap -p >&2

