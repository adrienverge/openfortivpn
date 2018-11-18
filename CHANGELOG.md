Openfortivpn Changelog
======================

Legend
------

* [+] new feature, improvement
* [-] bug fix
* [~] change in behavior

Releases
--------

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
* [-] Prioritize command line arguments over config file parameters
* [~] Dynamically allocate routing buffer and therefore allow larger routing table
* [+] Support systemd notification upon tunnel up
* [+] Support building in a separate directory
* [~] Change the way to read passwords such that backspace etc. should work as usual
* [~] Rationalize DNS options: pppd and openfortivpn were updating /etc/resolv.conf.
      Check man page and help output for the documentation of the current behavior.

### Earlier Versions

Please see Github [commit history](https://github.com/adrienverge/openfortivpn/commits)

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
