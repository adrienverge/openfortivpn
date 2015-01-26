openfortivpn
============

openfortivpn is a client for PPP+SSL VPN tunnel services. It spawns a pppd
process and operates the communication between the gateway and this process.

It is compatible with Fortinet VPNs.

Examples
--------

* Simply connect to a VPN:

  ```
  openfortivpn vpn-gateway:8443 --username=foo --password=bar
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
  ```

Building from source
--------------------

1.  Install build dependencies.

    * Fedora: `openssl-devel`
    * Ubuntu: `libssl-dev`
    * Arch Linux: `openssl`

2.  Build and install.

    ```
    aclocal && autoconf && automake --add-missing
    ./configure --prefix=/
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

Contributing
------------

Feel free to make pull requests!

C coding style should follow the [Linux kernel Documentation/CodingStyle](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/CodingStyle?id=refs/heads/master).
