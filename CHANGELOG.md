Openfortivpn Changelog
======================

Legend
------

* [+] new feature or improvement
* [-] bug fix
* [~] change in behavior

Releases
--------

This high level changelog is usually updated when a release is tagged.
On the master branch there may be changes that are not (yet) described here.

### 1.22.1

* [-] do not advertise we talk compressed HTTP - we don't

### 1.22.0

* [-] make sure Homebrew packages for macOS are built with --enable-legacy-pppd
* [~] do not print TLS socket options in log (revert change from 1.16.0)
* [+] add option to specify SNI
* [~] change most occurrences of "SSL" to "TLS" in user-visible text

### 1.21.0

* [~] fix "Peer refused to agree to his IP address" message, again
* [~] deprecate option --plugin
* [-] better masking of password in logs
* [-] break on reading 0 from ppp pty, for non-Linux systems

### 1.20.5

* [-] revert previous fix from 1.20.4, make it optional

### 1.20.4

* [-] fix "Peer refused to agree to his IP address" message

### 1.20.3

* [~] minor change in a warning message
* [+] documentation improvement
* [+] minor changes in build and test files

### 1.20.2

* [-] fix regression: do attempt to apply duplicate routes, log INFO instead of WARN
* [-] minor changes in log messages

### 1.20.1

* [-] fix version string in configure.ac

### 1.20.0

* [-] fix incorrect empty HDLC frame detection causing connection drops
* [+] increase the inbound HTTP buffer capacity
* [-] fix a few log messages
* [-] fix innocuous memory leaks when parsing options
* [+] prepend "SVPNCOOKIE=" to the cookie if missing
* [~] drop support for openssl < 1.0.2

### 1.19.0

* [-] fix "Peer refused to agree to our IP address" message
* [+] avoid setting duplicate routes
* [~] remove obsolete code that reads non-XML config from FortiOS 4
* [-] improve warning message when reading options from config file

### 1.18.0

* [+] add new options to delegate the authentication to external programs
* [-] minor fixes in documentation

### 1.17.3

* [-] fix regression: spurious warning message after reading config

### 1.17.2

* [-] fix memory leak when reading user input
* [-] improve calls to getsockopt() and associated debug output
* [+] allow reading config from process substitution
* [-] work around CodeQL false positives, improving code at the same time
* [~] change type of systemd.service from simple to notify

### 1.17.1

* [-] fix regression: enable OpenSSL engines by default
* [-] fix typos found by codespell
* [-] fix LGTM alerts

### 1.17.0

* [-] make OpenSSL engines optional
* [+] document and favor --pinentry over plain text password in configuration file
* [-] fix buffer overflow and other errors in URI espcaping for --pinentry
* [~] use different --pinentry hints for different hosts, usernames and realms
* [-] fix memory management errors related to --user-agent option

### 1.16.0

* [+] support for user key pass phrase
* [~] add a space at the end of the OTP prompt
* [-] improve tunnel speed on macOS
* [-] modify memory allocation in the tunnel configuration structure
* [+] openfortivpn returns the PPP exit status
* [+] print TLS socket options in log

### 1.15.0

* [-] fix issue sending pin codes
* [+] add command line option to bind to specific interface
* [+] use different hints for OTP and 2FA
* [+] remove password from /proc/#/cmd
* [+] extend OTP to allow FTM push
* [+] add preliminary support for host checks
* [-] don't accept route to the vpn gateway
* [-] fix byte counter in pppd_write

### 1.14.1

* [-] fix out of bounds array access

### 1.14.0

* [+] add git commit id in debug output
* [-] do not use interface ip for routing on linux
* [-] avoid extra hop on interface for default route
* [+] clean up, updates and improvements in the build system
* [+] increase the inbound HTTP buffer capacity when needed
* [+] print domain search list to output
* [+] add systemd service file
* [+] add systemd notification when stopping
* [+] allow logging with both smartcard and username
* [+] fix GCC 9 and clang warnings
* [+] bump default minimal TLS version from TLSv1.0 to TLSv1.2
* [-] fix a couple coverity warnings

### 1.13.3

* [-] fix a coverity warning
* [-] cross-compile: do not check resolvconf on the host system

### 1.13.2

* [-] properly build on FreeBSD, even if ppp is not installed at configure time

### 1.13.1

* [-] build in the absence of resolvconf

### 1.13.0

* [-] avoid unsupported versions of resolvconf
* [~] add configure and command line option for resolvconf
* [-] increase BUFSIZ
* [-] reinitialize static variables with the --persistent option
* [-] fix Makefile incompatibility with BSD sed
* [-] fix a memory leak in ipv4_add_nameservers_to_resolv_conf

### 1.12.0

* [-] fix CVE-2020-7043: TLS Certificate CommonName NULL Byte Vulnerability
* [-] fix CVE-2020-7042: use of uninitialized memory in X509_check_host
* [-] fix CVE-2020-7041: incorrect use of X509_check_host (regarding return value).
* [-] always hide cleartest password in -vv output
* [+] add a clear warning about sensitive information in the debug output
* [+] add a hint in debug output when password is read from configuration file
* [-] fix segfault when connecting with empty password
* [+] use resolvconf if available to update resolv.conf file
* [~] replace semicolon by space in dns-suffix string

### 1.11.0

* [+] allow to connect with empty password (and with smartcard instead of username)
* [~] properly handle manipulations of resolv.conf
* [+] support dns-suffix feature
* [-] several codacy fixes
* [+] Add smartcard support with openssl-engine
* [-] correctly shift masks for cidr notation on MAC
* [-] one-byte fix to build with lcc compiler
* [-] pass space character as %20 instead of encoding it as '+'

### 1.10.0

* [-] fix openssl 1.1.x compatibility issues
* [~] Connect to old TLSv1.0 software - override new openssl defaults.
* [~] suppress cleartext password in debug detail output / add new verbosity level
* [~] increase speed setting for pppd
* [-] work around EAGAIN issue on FreeBSD
* [~] configure.ac: rt_dst: don't run tests when option is passed
* [~] configure.ac: don't check file path if --with/--disable specified
* [+] userinput: pass a hint to the pinentry program
* [-] tunnel: make pppd default to logging to stderr
* [-] tunnel: pass our stderr to the pppd slave

### 1.9.0

* [+] update of the man page, especially about the dns settings
* [+] improved configure output: show detected paths for use at runtime
* [-] correctly convert parsed values, fix for an issue e.g. on Raspbian
* [+] make search string for the otp-prompt configurable
* [+] add an option to specify a configurable delay during otp authentication
* [~] make the options that control usepeerdns more consistent

### 1.8.1

* [~] Support longer passwords by allocation of a larger buffer
* [-] With version 1.8.0 /etc/resolv.conf was not updated anymore in some situations.
  To avoid this regression the change "Rationalize DNS options" has been reverted again
  to restore the behavior of versions up to 1.7.1.
* [-] Correctly use realm together with two factor authentication
* [~] If no port is specified use standard https port similar as vendor client
* [-] Fix value of Accept-Encoding request header
* [-] Bugfix in url_encode for non alphanumerical characters
* [-] HTML URL Encoding with uppercase characters
* [-] Honor Cipher-list option
* [~] Improved detection of pppd/ppp client during configure stage

### 1.8.0

* [-] On Mac OSX and FreeBSD correctly use interface name for routing
* [~] On Mac OSX and FreeBSD moved netstat parsing output to higher debug level
* [~] When logging traffic also show http traffic (not only tunneled traffic)
* [~] Improve error message in case of login failure
* [~] Require root privileges for running. They are needed at various places.
  Previously, just a warning was issued, but in later stage things have failed.
* [-] On Mac OSX the protection of the route to the vpn gateway may have failed
* [~] Invert order of ssl libraries (this may help linking on some platforms)
* [+] Add FreeBSD support and redesigned the autoconf mechanism
* [+] Support building with gcc 8
* [-] Prioritize command line arguments over configuration file parameters
* [~] Dynamically allocate routing buffer and therefore allow larger routing table
* [+] Support systemd notification upon tunnel up
* [+] Support building in a separate directory
* [~] Change the way to read passwords such that backspace etc. should work as usual
* [~] Rationalize DNS options: pppd and openfortivpn were updating /etc/resolv.conf.
  Check man page and help output for the documentation of the current behavior.

### 1.7.1

* [~] Be more tolerant about white space in configuration file
* [~] Make better usage of pkg-config
* [~] Rework linking against OpenSSL
* [-] Build again on Mac OSX where pthread_mutexattr_setrobust is not available

### 1.7.0

* [~] Correctly set up route to vpn gateway (add support for some particular situations)
* [+] Support two factor authentication with configuration file (for NM-plugin)
* [~] Change the ip address in the pppd call parameters by a rfc3330 test-net address
* [-] Correctly report the exit status codes of pppd
* [+] Add --pppd-call option
* [~] Use X509_check_host instead of explicit CN match
* [+] Add --persistent option
* [~] Improve autoconf (check for pkg-conf before using, improve error messages, etc.)

### 1.6.0

* [-] Fix possible buffer overflow in long requests
* [~] Code improvements in terms of header inclusion and some other coverity warnings
* [+] Add proxy support
* [~] Use the compiled-in fixed full path to pppd
* [+] Support pppd ifname option
* [+] Print a clear error message at runtime if pppd does not exist
* [+] Print clear text error messages of pppd upon failure
* [~] Existing configuration file is not overwritten anymore at installation time
* [~] Increase the accepted cookie size and align the error behavior according to RFCs
* [-] More gracefully handle unexpected content of resolv.conf
* [~] Dynamically allocate memory for split routes and thus support larger numbers of routes

### 1.5.0

* [~] Improve error handling around the call of pppd
* [+] Add half-internet-routes option
* [-] realm was not recognized in the configuration file
* [~] Switch from no-routes and no-dns to set-routes and set-dns option
* [+] Add pppd-no-peerdns and pppd-log option
* [~] Allow passing the otp via the configuration file for use with NetworkManager plugin
* [-] Fix issues initializing memory and with build system
* [+] Support building against Openssl 1.1
* [~] use pkg-config for configuration of openssl instead of configure option
* [-] Fix string handling of the command line arguments

### 1.4.0

* [+] Allow to specify openssl location via configure option
* [+] Introduce autotools build script autogen.sh
* [~] Further increase possible number of split routes
* [-] Fix locking issues on Mac OS X
* [~] Rework signal handling: Handle SIGTERM as SIGINT and ignore SIGHUP

### 1.3.1

* [~] When calling pppd allow passing an ipparam for use in pppd ip-up/down scripts
* [-] Command line option -o was not recognized before
* [~] Improve Mac OSX support and parse netstat output to obtain routing information
* [-] Fix segmentation fault when a gateway route is added on Mac OSX
* [-] Fix buffer overflow for name server entries
* [~] Increase possible number of split routes
* [-] Do not remove route to vpn gateway if it has existed before connecting
* [~] Load OS trusted certificate stores
* [~} When setting up routes protect the route to the vpn gateway
* [-] Add gateway flag to routes that may not be reachable directly at the tunnel end
* [-] Correctly detect if pushed routes have a gateway
* [-] Correctly mark the route to the vpn gateway as a host route
* [-] Clean up routing table upon termination

### 1.3.0

* [+] Support vpn connections over an already existing ppp connection
* [-] Fix for diagnostic message colors invisible on light background
* [-] Bugfix for building with clang
* [+] Add token-based one-time password support
* [+] Add Mac OSX support
* [+] Support logging via syslog
* [-] Honor sysconfdir during runtime, i.e. when loading default configuration
* [~] Disable insecure openssl default protocols/ciphers

### 1.2.0

* [+] Support login with client certificate, key, and ca-file specified in configuration file
* [~] Use more meaningful error codes when loading config fails
* [-] Correctly report errors of hostname lookup
* [+] Add an option not to ask ppp peer for dns servers
* [-] Fix array bounds error for trusted cert string
* [-] Fix compiler warning about type cast around getchar
* [-] Properly initialize memory for tunnel structure to avoid undeterministic behavior
* [-] Properly initialize pointer in auth_log_in to avoid crash on http_request
* [-] Fix buffer overflow in parse_config

### 1.1.4

* [-] Fix new GCC 6 strict-aliasing errors
* [-] For split routes use interface if no gateway address is assigned in received route
* [-] Fix rewrite of resolv.conf with non null-terminated buffer
* [~] Perform two factor authentication also with zero-length tokeninfo

### 1.1.3

* [~] Support set-dns and set-routes flag from configuration file as well
* [-] Properly URL-encode values sent in http requests
* [+] Add support for realm authentication
* [+] Add support for two factor authentication

### 1.1.2

* [-] Fix incompatible-pointer-types compiler error for x86 architectures
* [~] Increase COOKIE_SIZE (again)

### 1.1.1

* [~] Update of Makefile to treat all warnings as errors
* [~] Increase COOKIE_SIZE to 240 as the SVPNCOOKIE is longer in newer FortiOS versions

### 1.1.0

* [~] Rename --plugin to --pppd-plugin for consistency with other pppd-related options
* [-] NUL terminate the config buffer
* [-] Fix an off-by-one error when reading a quad-dotted attribute from xml
* [+] Add support for client keys and certificates
* [~] Extend the split VPN support with older FortiOS servers
* [+] Add a config parser to handle received non-xml content
* [~] Allow omitting the gateway for split routes
* [~] Allow omitting DNS servers
* [-] Fix a memory leak in auth_get_config
* [+] Support split routes
* [+] Export the configuration of routes and gateway to environment
* [~] Several improvements around establishing the tunnel connection and http traffic
* [+] Allow using a custom CA
* [-] Turn on TLS verification, check the hostname at least for the CN
* [+] Add --plugin option
* [-] Fix a format string warning in do_log_packet
* [~] Improved debugging output
* [~] Restore default route

### 1.0.1

* [~] Better error messages in /etc/resolv.conf helpers
* [~] Use better colors for warnings and error messages and only if output is a tty
* [-] Fix parsing of "trusted-cert" in configuration file
* [~] Add --pedantic to CFLAGS
* [+] Add ability to type password interactively
* [+] Verify gateway's X509 certificate
* [-] Don't delete nameservers at tear down if they were here before
* [~] Set /etc/openfortivpn/config not readable by other users
* [+] Add ability to use a configuration file

### 1.0.0

* Start tracking openfortivpn - in this version with the following features:
```
Usage: openfortivpn <host>:<port> -u <user> -p <pass>
                    [--no-routes] [--no-dns] [--pppd-log=<filename>]
                    [-v|-q]
       openfortivpn --help
       openfortivpn --version
```

### Details of the changes

This is a high level changelog meant to provide a rough overview about the version history of openfortivpn. Please see the Github [commit history](https://github.com/adrienverge/openfortivpn/commits) for more details of the individual changes listed here, and for a complete list of the internal code changes.

More Information
----------------

* For a list of known issues please check the
  [issues list](https://github.com/adrienverge/openfortivpn/issues) on GitHub.

* We try to avoid backwards incompatible changes, but sometimes it is not
  avoidable. When we are aware of compatibility issues, then we recommend to
  check the documentation in the above changelog. When changes turn out to break
  things for some specific configurations after we have tagged a new release,
  the issues list is the right place to report it, so that we can add a hint in
  the changelog for the subsequent release.
