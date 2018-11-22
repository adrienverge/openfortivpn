Openfortivpn Changelog
======================

Legend
------

*  [+] new feature, improvement
*  [-] bug fix
*  [~] change in behavior

Releases
--------

### Upcoming release (current master)
Note: this section still has to be reviewed. 

*  [-] Bugfix in url_encode for non alphanumerical characters
*  [-] HTML URL Encoding with uppercase characters
*  [-] Honor Cipher-list option 
*  [~] Improved detection of pppd/ppp client during configure stage 

### 1.8.0

*  [-] On Mac OSX and FreeBSD correctly use interface name for routing
*  [~] On Mac OSX and FreeBSD moved netstat parsing output to higher debug level
*  [~] When logging traffic also show http traffic (not only tunneled traffic)
*  [~] Improve error message in case of login failure
*  [~] Require root privileges for running. They are needed at various places.
       Previously, just a warning was issued, but in later stage things have failed.
*  [-] On Mac OSX the protection of the route to the vpn gateway may have failed
*  [~] Invert order of ssl libraries (this may help linking on some platforms)
*  [+] Add FreeBSD support and redesigned the autoconf mechanism
*  [+] Support building with gcc 8
*  [-] Prioritize command line arguments over config file parameters
*  [~] Dynamically allocate routing buffer and therefore allow larger routing table
*  [+] Support systemd notification upon tunnel up
*  [+] Support building in a separate directory
*  [~] Change the way to read passwords such that backspace etc. should work as usual
*  [~] Rationalize DNS options: pppd and openfortivpn were updating /etc/resolv.conf.
       Check man page and help output for the documentation of the current behavior.

### 1.7.1

*  [~] Be more tolerant about white space in config file
*  [~] Make better usage of pkg-config 
*  [~] Rework linking against OpenSSL
*  [-] Build again on Mac OSX where pthread_mutexattr_setrobust is not available

### 1.7.0

*  [~] Correctly set up route to vpn gateway (add support for some particular situations)
*  [+] Support two factor authentication with config file (for NM-plugin)
*  [~] Change the ip address in the pppd call parameters by a rfc3330 test-net address
*  [-] Correctly report the esit status codes of pppd
*  [+] Add --pppd-call option
*  [~] Use X509_check_host instead of explicit CN match
*  [+] Add --persistent option
*  [~] Improve autoconf (check for pkg-conf before using, improve error messages, etc.)


### Earlier Versions

Please see Github [commit history](https://github.com/adrienverge/openfortivpn/commits)

More Information
----------------

*  For a list of known issues please check the
   [issues list](https://github.com/adrienverge/openfortivpn/issues) on GitHub.
*  We try to avoid backwards incompatible changes, but sometimes it is not
   avoidable. When we are aware of compatibility issues, then we recommend to
   check the documentation in the above changelog. When changes turn out to break
   things for some specific configurations after we have tagged a new release,
   the issues list is the right place to report it, so that we can add a hint in
   the changelog for the subsequent release.
