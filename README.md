openfortivpn
============

openfortivpn is a client for PPP+TLS VPN tunnel services.
It spawns a pppd process and operates the communication between the gateway and
this process.

It is compatible with Fortinet VPNs.

Usage
-----

```shell
man openfortivpn
```

Examples
--------

* Simply connect to a VPN:
  ```shell
  openfortivpn vpn-gateway:8443 --username=foo
  ```

* Connect to a VPN using an authentication realm:
  ```shell
  openfortivpn vpn-gateway:8443 --username=foo --realm=bar
  ```

* Store password securely with a pinentry program:
  ```shell
  openfortivpn vpn-gateway:8443 --username=foo --pinentry=pinentry-mac
  ```

* Connect with a user certificate and no password:
  ```shell
  openfortivpn vpn-gateway:8443 --username= --password= --user-cert=cert.pem --user-key=key.pem
  ```

* Connect using SAML login:
  ```shell
  openfortivpn vpn-gateway:8443 --saml-login
  ```

* Don't set IP routes and don't add VPN nameservers to `/etc/resolv.conf`:
  ```shell
  openfortivpn vpn-gateway:8443 -u foo --no-routes --no-dns --pppd-no-peerdns
  ```

* Using a configuration file:
  ```shell
  openfortivpn -c /etc/openfortivpn/my-config
  ```

  With `/etc/openfortivpn/my-config` containing:
  ```ini
  host = vpn-gateway
  port = 8443
  username = foo
  set-dns = 0
  pppd-use-peerdns = 0
  # X509 certificate sha256 sum, trust only this one!
  trusted-cert = e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db
  ```

* For the full list of config options, see the `CONFIGURATION` section of
  ```shell
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

```ini
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
smartcards may work too. On Mac OS X Mojave it is known that the pkcs engine-by-id
is not found.

Installing
----------

### Installing existing packages

Some Linux distributions provide `openfortivpn` packages:
* [Fedora / CentOS](https://packages.fedoraproject.org/pkgs/openfortivpn)
* [openSUSE / SLE](https://software.opensuse.org/package/openfortivpn)
* [Gentoo](https://packages.gentoo.org/packages/net-vpn/openfortivpn)
* [NixOS](https://github.com/NixOS/nixpkgs/tree/master/pkgs/tools/networking/openfortivpn)
* [Arch Linux](https://archlinux.org/packages/extra/x86_64/openfortivpn)
* [Debian](https://packages.debian.org/stable/openfortivpn)
* [Ubuntu](https://packages.ubuntu.com/search?keywords=openfortivpn)
* [Solus](https://dev.getsol.us/source/openfortivpn/)
* [Alpine Linux](https://pkgs.alpinelinux.org/package/edge/testing/x86_64/openfortivpn)

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
    ```text
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

    If targeting platforms with pppd < 2.5.0 such as current version of macOS,
    we suggest you configure with option --enable-legacy-pppd:

    ```shell
    ./autogen.sh
    ./configure --prefix=/usr/local --sysconfdir=/etc --enable-legacy-pppd
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
```shell
visudo -f /etc/sudoers.d/openfortivpn
```
```text
Cmnd_Alias  OPENFORTIVPN = /usr/bin/openfortivpn

%adm       ALL = (ALL) OPENFORTIVPN
```
Adapt the above example by changing the `openfortivpn` path or choosing
a group different from `adm` - such as a dedicated `openfortivpn` group.

**Warning**: Make sure only trusted users can run openfortivpn as root!
As described in [#54](https://github.com/adrienverge/openfortivpn/issues/54),
a malicious user could use `--pppd-plugin` and `--pppd-log` options to divert
the program's behaviour.

SSO/SAML/2FA
------------

In some cases, the server may require the VPN client to load and interact
with a web page containing JavaScript. Depending on the complexity of the
web page, interpreting the web page might be beyond the reach of a command
line program such as openfortivpn.

In such cases, you may use an external program spawning a full-fledged
web browser such as
[openfortivpn-webview](https://github.com/gm-vm/openfortivpn-webview)
to authenticate and retrieve a session cookie. This cookie can be fed
to openfortivpn using option `--cookie-on-stdin`. Obviously, such a
solution requires a graphic session.

When started using `--saml-login` the program creates a web server that
accepts SAML login requests. To login using SAML you just have to open
`<your-vpn-domain>/remote/saml/start?redirect=1` and follow the login steps.
At the end of the login process the page will be redirected to
`http://127.0.0.1:8020/?id=<session-id>`

Contributing
------------

Feel free to make pull requests!

C coding style should follow the
[Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html).
