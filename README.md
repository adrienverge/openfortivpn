openfortivpn
============

openfortivpn is a client for PPP+SSL VPN tunnel services. It spawns a pppd
process and operates the communication between the gateway and this process.

It is compatible with Fortinet VPNs.

Examples
--------

* Simply connect to a VPN:

  ```
  openfortivpn vpn-gateway:8443 --username=foo
  ```

* Connect to a VPN using an authentication realm:

  ```
  openfortivpn vpn-gateway:8443 --username=foo --realm=bar
  ```

* Don't set IP routes and don't add VPN nameservers to `/etc/resolv.conf`:

  ```
  openfortivpn vpn-gateway:8443 -u foo -p bar --no-routes --no-dns
  ```

* Using a config file:

  ```
  openfortivpn
  ```

  With `/etc/openfortivpn/config` containing:

  ```
  host = vpn-gateway
  port = 8443
  username = foo
  password = bar
  set-dns = 0
  set-routes = 0
  # X509 certificate sha256 sum, trust only this one!
  trusted-cert = e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db
  ```

Installing
----------

openfortivpn is packaged for Fedora, Gentoo and NixOS under the package name
`openfortivpn`.

For other distros, you'll need to build and install from source:

1.  Install build dependencies.

    * Fedora: `gcc` `automake` `autoconf` `openssl-devel`
    * Ubuntu: `automake` `autoconf` `libssl-dev`
    * Debian: `gcc` `automake` `autoconf` `libssl-dev`
    * Arch Linux: `automake` `autoconf` `openssl`
    * Gentoo Linux: `net-dialup/ppp`
    * macOS: `automake` `autoconf` `homebrew/versions/openssl101`

  If You manage your kernel yourself, ensure to compile those modules:

  ```
  CONFIG_PPP=m
  CONFIG_PPP_ASYNC=m
  ```

  On macOS, install homebrew to install the build dependencies:
  ```
  /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
  ```

2.  Build and install.

    ```
    aclocal && autoconf && automake --add-missing
    ./configure --prefix=/usr --sysconfdir=/etc
    make
    sudo make install
    ```

  On macOS :
  ```
  brew install automake autoconf homebrew/versions/openssl101
  aclocal && autoconf && automake --add-missing
  export CPPFLAGS="-I/usr/local/opt/openssl101/include"
  export LDFLAGS="-L/usr/local/opt/openssl101/lib"
  ./configure --prefix=/usr/local --sysconfdir=/etc
  make
  sudo make install
  ```

Running as root?
----------------

openfortivpn needs elevated privileges at three steps during tunnel set up:

* when spawning a `/usr/sbin/pppd` process;
* when setting IP routes through VPN (when the tunnel is up);
* when adding nameservers to `/etc/resolv.conf` (when the tunnel is up).

For these reasons, you may need to use `sudo openfortivpn`. If you need it to
be usable by non-sudoer users, you might consider adding an entry in
`/etc/sudoers`.

For example:
`visudo -f /etc/sudoers.d/openfortivpn`
```
Cmnd_Alias  OPENFORTIVPN = /usr/bin/openfortivpn

%adm       ALL = (ALL) OPENFORTIVPN
```

**Warning**: Make sure only trusted users can run openfortivpn as root! As
described in #54, a malicious user could use `--ppp-plugin` and `--ppd-log`
options to divert the program's behaviour.

Contributing
------------

Feel free to make pull requests!

C coding style should follow the [Linux kernel Documentation/CodingStyle](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/process/coding-style.rst?id=refs/heads/master).
