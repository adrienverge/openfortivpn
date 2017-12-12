openfortivpn
============

openfortivpn is a client for PPP+SSL VPN tunnel services.  
It spawns a pppd process and operates the communication between the gateway and 
this process.

It is compatible with Fortinet VPNs.



--------
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
  openfortivpn vpn-gateway:8443 -u foo -p bar --no-routes --no-dns --pppd-no-peerdns
  ```
* Using a config file:
  ```
  openfortivpn -c /etc/openfortivpn/my-config
  ```

  With `/etc/openfortivpn/my-config` containing:
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



----------
Installing
----------

openfortivpn is packaged for [Fedora](https://admin.fedoraproject.org/pkgdb/package/rpms/openfortivpn/), [openSUSE / SLE](https://software.opensuse.org/package/openfortivpn), [Gentoo](https://packages.gentoo.org/packages/net-vpn/openfortivpn), [NixOS](https://github.com/NixOS/nixpkgs/tree/master/pkgs/tools/networking/openfortivpn), [Arch Linux](https://aur.archlinux.org/packages/openfortivpn) and [Solus](https://packages.solus-project.com/unstable/o/openfortivpn/) under the package name `openfortivpn`.

For other distros, you'll need to build and install from source:

1.  Install build dependencies.

    * RHEL/CentOS/Fedora: `gcc` `automake` `autoconf` `openssl-devel` `pkg-config`
    * Debian/Ubuntu: `gcc` `automake` `autoconf` `libssl-dev` `pkg-config`
    * Arch Linux: `gcc` `automake` `autoconf` `openssl` `pkg-config`
    * Gentoo Linux: `net-dialup/ppp` `pkg-config`
    * openSUSE: `gcc` `automake` `autoconf` `libopenssl-devel` `pkg-config`
    * macOS(Homebrew): `automake` `autoconf` `openssl@1.0` `pkg-config`

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
    brew install automake autoconf openssl@1.0
    ```

    On macOS, install 'openfortivpn'...
    ```
    brew install openfortivpn
    ```
    ...**or** build a version of your choice from source following the instructions in step 2.


2.  Build and install.

    ```shell
    ./autogen.sh
    ./configure --prefix=/usr/local --sysconfdir=/etc
    make
    sudo make install
    ```

    If you need to specify the openssl location you can set the
    `$PKG_CONFIG_PATH` environment variable.


----------------
Running as root?
----------------

openfortivpn needs elevated privileges at three steps during tunnel set up:

* when spawning a `/usr/sbin/pppd` process;
* when setting IP routes through VPN (when the tunnel is up);
* when adding nameservers to `/etc/resolv.conf` (when the tunnel is up).

For these reasons, you may need to use `sudo openfortivpn`.  
If you need it to be usable by non-sudoer users, you might consider adding an 
entry in `/etc/sudoers`.

For example:
`visudo -f /etc/sudoers.d/openfortivpn`
```
Cmnd_Alias  OPENFORTIVPN = /usr/bin/openfortivpn

%adm       ALL = (ALL) OPENFORTIVPN
```

**Warning**: Make sure only trusted users can run openfortivpn as root!  
As described in [#54](https://github.com/adrienverge/openfortivpn/issues/54), 
a malicious user could use `--pppd-plugin` and `--pppd-log` options to divert 
the program's behaviour.



------------
Contributing
------------

Feel free to make pull requests!

C coding style should follow the 
[Linux kernel Documentation/CodingStyle](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/process/coding-style.rst?id=refs/heads/master).
