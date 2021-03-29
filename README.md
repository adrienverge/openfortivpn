openfortivpn
============

openfortivpn is a client for PPP+SSL VPN tunnel services.
It spawns a pppd process and operates the communication between the gateway and
this process.

It is compatible with Fortinet VPNs.

Usage
--------

```
man openfortivpn
```

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

* Store password securely with a pinentry program:
  ```
  openfortivpn vpn-gateway:8443 --username=foo --pinentry=pinentry-mac
  ```

* Don't set IP routes and don't add VPN nameservers to `/etc/resolv.conf`:
  ```
  openfortivpn vpn-gateway:8443 -u foo --no-routes --no-dns --pppd-no-peerdns
  ```
* Using a configuration file:
  ```
  openfortivpn -c /etc/openfortivpn/my-config
  ```

  With `/etc/openfortivpn/my-config` containing:
  ```
  host = vpn-gateway
  port = 8443
  username = foo
  set-dns = 0
  pppd-use-peerdns = 0
  # X509 certificate sha256 sum, trust only this one!
  trusted-cert = e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db
  ```

* For the full list of config options, see the `CONFIG FILE` section of
  ```
  man openfortivpn
  ```

Smartcard
---------

Smartcard support needs `openssl pkcs engine` and `opensc` to be installed.
The pkcs11-engine from libp11 needs to be compiled with p11-kit-devel installed.
Check [#464](https://github.com/adrienverge/openfortivpn/issues/464) for a discussion
of known issues in this area.

To make use of your smartcard put at least `pkcs11:` to the user-cert config or commandline
option. It takes the full or a partial PKCS#11 token URI.

```
user-cert = pkcs11:
user-cert = pkcs11:token=someuser
user-cert = pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=012345678;token=someuser
username =
password =
```

In most cases `user-cert = pkcs11:` will do it, but if needed you can get the token-URI
with `p11tool --list-token-urls`.

Multiple readers are currently not supported.

Smartcard support has been tested with Yubikey under Linux, but other PIV enabled
smartcards may work too. On Mac OS X Mojave it is known that the pkcs engine-by-id is not found.

Installing
----------

### Installing existing packages

Some Linux distributions provide `openfortivpn` packages:
* [Fedora / CentOS](https://apps.fedoraproject.org/packages/openfortivpn)
* [openSUSE / SLE](https://software.opensuse.org/package/openfortivpn)
* [Gentoo](https://packages.gentoo.org/packages/net-vpn/openfortivpn)
* [NixOS](https://github.com/NixOS/nixpkgs/tree/master/pkgs/tools/networking/openfortivpn)
* [Arch Linux](https://www.archlinux.org/packages/community/x86_64/openfortivpn)
* [Debian (testing)](https://packages.debian.org/buster/openfortivpn)
* [Ubuntu (bionic and later)](https://packages.ubuntu.com/search?keywords=openfortivpn) and [pre-bionic (ppa)](https://launchpad.net/~ar-lex/+archive/ubuntu/fortisslvpn)
* [Solus](https://dev.getsol.us/source/openfortivpn/)

On macOS both [Homebrew](https://formulae.brew.sh/formula/openfortivpn) and
[MacPorts](https://ports.macports.org/port/openfortivpn)
provide an `openfortivpn` package.
Either [install Homebrew](https://brew.sh/) then install openfortivpn:
```shell
# Install 'Homebrew'
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

# Install 'openfortivpn'
brew install openfortivpn
```

or [install MacPorts](https://www.macports.org/install.php) then install openfortivpn:
```shell
# Install 'openfortivpn'
sudo port install openfortivpn
```

A more complete overview can be obtained from [repology](https://repology.org/project/openfortivpn/versions).

### Building and installing from source

For other distros, you'll need to build and install from source:

1.  Install build dependencies.

    * RHEL/CentOS/Fedora: `gcc` `automake` `autoconf` `openssl-devel` `make` `pkg-config`
    * Debian/Ubuntu: `gcc` `automake` `autoconf` `libssl-dev` `make` `pkg-config`
    * Arch Linux: `gcc` `automake` `autoconf` `openssl` `pkg-config`
    * Gentoo Linux: `net-dialup/ppp` `pkg-config`
    * openSUSE: `gcc` `automake` `autoconf` `libopenssl-devel` `pkg-config`
    * macOS (Homebrew): `automake` `autoconf` `openssl@1.1` `pkg-config`
    * FreeBSD: `automake` `autoconf` `libressl` `pkgconf`

    On Linux, if you manage your kernel yourself, ensure to compile those modules:
    ```
    CONFIG_PPP=m
    CONFIG_PPP_ASYNC=m
    ```

    On macOS, install 'Homebrew' to install the build dependencies:
    ```shell
    # Install 'Homebrew'
    /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

    # Install Dependencies
    brew install automake autoconf openssl@1.1 pkg-config

    # You may need to make this openssl available to compilers and pkg-config
    export LDFLAGS="-L/usr/local/opt/openssl/lib $LDFLAGS"
    export CPPFLAGS="-I/usr/local/opt/openssl/include $CPPFLAGS"
    export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"
    ```

2.  Build and install.

    ```shell
    ./autogen.sh
    ./configure --prefix=/usr/local --sysconfdir=/etc
    make
    sudo make install
    ```

    If you need to specify the openssl location you can set the `$PKG_CONFIG_PATH`
    environment variable. For fine-tuning check the available configure arguments
    with `./configure --help` especially when you are cross compiling.

    Finally, install runtime dependency `ppp` or `pppd`.

Running as root?
----------------

openfortivpn needs elevated privileges at three steps during tunnel set up:

* when spawning a `/usr/sbin/pppd` process;
* when setting IP routes through VPN (when the tunnel is up);
* when adding nameservers to `/etc/resolv.conf` (when the tunnel is up).

For these reasons, you need to use `sudo openfortivpn`.
If you need it to be usable by non-sudoer users, you might consider adding an
entry in `/etc/sudoers` or a file under `/etc/sudoers.d`.

For example:
`visudo -f /etc/sudoers.d/openfortivpn`
```
Cmnd_Alias  OPENFORTIVPN = /usr/bin/openfortivpn

%adm       ALL = (ALL) OPENFORTIVPN
```
Adapt the above example by changing the `openfortivpn` path or choosing
a group different from `adm` - such as a dedicated `openfortivpn` group.

**Warning**: Make sure only trusted users can run openfortivpn as root!
As described in [#54](https://github.com/adrienverge/openfortivpn/issues/54),
a malicious user could use `--pppd-plugin` and `--pppd-log` options to divert
the program's behaviour.

Contributing
------------

Feel free to make pull requests!

C coding style should follow the
[Linux kernel Documentation/CodingStyle](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/process/coding-style.rst?id=refs/heads/master).
