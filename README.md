sshcertauth
===========

This is *sshcertauth*, a set of **server-side** PHP and Bash scripts that enable
users to use their X.509 certificate to get the authorization to perform SSH.
**No software is required to be installed on the client.**


Rationale
---------

These server-side only scripts address the problem of giving SSH access to a
user who already happens to have a proper X.509 certificate. The user can, in
principle, connect directly using its RSA private key, but *the server does
not have prior knowledge of its public counterpart*.

By installing these scripts only onto a server, we can leverage sshd and apache2
to perform a  two-step authentication, where the user:

 * points a browser to a web page (say: `https://hostname/auth`), where he/she
   is given the authorization to use SSH;
 * connects to the host with `ssh -i /path/to/my_rsa_key.pem user@hostname`.

The authorization given by the web browser relies on the fact that, while
authenticating through HTTPS by presenting a client certificate, client also
communicates the public key.

*sshcertauth* does the work of:

 * extracting the public key from the certificate in a HTTPS connection;
 * adding the key into the list of authorized keys read by sshd.

Each key might also be given an expiration: passed that, the key is going to be
deleted from the authorized keys list and the user will need to obtain the
authorization again.

Adding each SSH public key by hand can be a painful process when dealing with a
large number of users (like the Grid). If they already have a set of trusted
credentials, like a X.509 private key and certificate, it is a good thing to
exploit it for authentication; and if users don't have to install a new software
to use the system, it would be even better. This is exactly what I purpose with
*sshcertauth*.


Alternatives
------------

*[gsissh][1]*, is a modified version of both *ssh* (client) and *sshd* (server)
which directly supports certificate authentication, mostly used for the Grid.

*sshcertauth* is meant to be a lighter alternative to that approach. We should
note however that *gsissh*, being a Grid software, requires the user to issue a
[proxy certificate][2] which will be used for the authentication. It is then a
different thing, rather than an alternative, even if there are cases in which
they are mostly interchangeable in functionalities.

Since a proxy certificate has a very limited validity in time, also in this
case the authorization to use SSH (and all services requiring a proxy
certificate) has to be removed from time to time.

*sshcertauth* is to be preferred where it is unfeasible, or complicated, or
just annoying for the user to install "special" software in addition to the
tools he/she already knows: it requires only a web browser and the SSH client.

As said, *gsissh* supports all the extended features of a proxy certificate, while
sshcertauth only supports plain X.509 (as HTTPS only supports that). If Grid
functionality is required on the remote host, *gsissh* is then the proper
solution.

So *sshcertauth* cannot be definitely considered a replacement for *gsissh*.


Server configuration
--------------------

*sshcertauth* has been developed with the [do not reinvent the wheel][3]
philosophy:

> You shouldn't reinvent the wheel. Unless you plan on learning more about
> wheels, that is.

Instead of rewriting a new tool integrating everything, we have decided to rely
on some special configuration bits of:

 * sshd
 * apache2 with mod_ssl
 * sudo (and the sudoers file)
 * crontab

*sshcertauth* only provides a single PHP script (with some libraries) and a
single shell script to add some missing authentication intelligence.

In order to enable some specially required functionality, some PAM and LDAP
configuration might have to be performed as well.

### Where can I find the installation procedure?

 * [How to configure a sshcertauth server, step by step][4]


Author
------

Dario Berzano, <dario.berzano@cern.ch>


 [1]: http://grid.ncsa.illinois.edu/ssh/
 [2]: http://www.ietf.org/rfc/rfc3820.txt
 [3]: http://www.codinghorror.com/blog/2009/02/dont-reinvent-the-wheel-unless-you-plan-on-learning-more-about-wheels.html
 [4]: http://newton.ph.unito.it/~berzano/w/doku.php?id=proof:sshcertauth
