#!/bin/bash

#
# stage_key.sh -- by Dario Berzano <dario.berzano@cern.ch>
#
# Some description is still pending.
#

# Run as root
if [ "$USER" != 'root' ]; then
  exec sudo "$0" "$@"
fi

# Key is passed on stdin
export PubKey=$(cat)

# User name is the first argument, SSH keydir the second
export UserName="$1"
export SshKeyDir="$2"

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

# Is user name set?
if [ "$UserName" == '' ]; then
  echo 'Username not set' >&2
  exit 1
fi

# Full path to key
export FullKeyFilePath="$SshKeyDir/$UserName"

# Check if this key is already in the list of authorized ones for this username
# (useful if using the same Unix username for multiple users, as "pool account")
export PubKeyCore=`echo "$PubKey" | awk '{ print $2 }'`

# Now we start operating on a keyfile: let's create a lock directory for obvious
# safety reasons. The lock/wait operation stays in the mkdir command, which is
# atomic (on most local filesystems): if the creation of the lock directory
# fails, there already is a lock; we try again LockLimit times then we give up
export LockDir="$SshKeyDir/$UserName".lock
export LockLimit=5
export LockSuccess=1
export LockCount=0
while ! mkdir "$LockDir" 2> /dev/null; do
  if [ $LockCount == $LockLimit ]; then
    LockSuccess=0
    break
  fi
  sleep 1
  let LockCount++
done

# Remove lock in case of exit/abort/etc. (only sigkill is uninterruptible)
trap "rmdir $LockDir" 0

# At this point we've given up waiting
if [ $LockSuccess == 0 ]; then
  echo "Cannot obtain mutex on authorized keys file" >&2
  exit 1
fi

#
# From now on, every operation is locked
#

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
