sshcertauth
===========

This is sshcertauth, a bunch of PHP and Bash scripts to enable any standard SSH daemon to authenticate users by means of a public key automatically extracted from a certificate via a HTTPS connection.

It is meant to be a lighter alternative to [gsissh](http://grid.ncsa.illinois.edu/ssh/), a modified version of both ssh (client) and sshd (server) which directly supports certificate authentication, mostly used for the Grid.

Unlike gsissh, sshcertauth does not require **anything special** to be installed on the client side. The user must only have **ssh** and a web browser.

Rationale: enabling SSH access for many clients
-----------------------------------------------

After setting up the system, an authorized user will be capable of connecting via SSH to a certain server only by performing two simple steps:

 * Pointing a browser to `https://hostname/auth`
 * Connecting to the machine with `ssh -i ~/.globus/userkey.pem user@hostname`

**User's public key needn't be known by the server in advance**, and this is actually *sshcertauth*'s peculiarity: the first step communicates the public key to the server (via HTTPS), which actually adds it in an "authorized keys" database if authentication is successful.

Adding each SSH public key by hand can be a painful process when dealing with a large number of users (like the Grid). If they already have a set of trusted credentials, like a X.509 private key and certificate, it would be better to exploit it for authentication; and if users don't have to install a new software to use the system, it would be even better. This is exactly what I purpose with *sshcertauth*.

Server configuration
--------------------

*sshcertauth* is simple and "do not reinvent the wheel", also on the server side: rather than rewriting a big tool implementing everything, we can just rely on some configuration bits of:

 * sshd
 * apache2 with mod_ssl
 * sudo (and the sudoers file)

*sshcertauth* only provides a single PHP script (with some libraries) and a single shell script to add some authentication intelligence.

Optional parts include some PAM and LDAP configuration.

### Where can I find the installation procedure?

 * [How to configure a sshcertauth server, step by step](http://newton.ph.unito.it/~berzano/w/doku.php?id=proof:sshcertauth)

Author
------

Dario Berzano, <dario.berzano@cern.ch>
