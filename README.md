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

* Don't add VPN nameservers to /etc/resolv.conf:

  ```
  openfortivpn vpn-gateway:8443 -u foo -p bar --no-dns
  ```

* Log pppd output in file `pppd.log`:

  ```
  openfortivpn vpn-gateway:8443 -u foo -p bar --pppd-log=pppd.log
  ```

Build from source
-----------------

1.  Install build dependencies.

    * Fedora: `openssl-devel`
    * Ubuntu: `libssl-dev`
    * Arch Linux: `openssl`

2.  Build and install.

    ```
    aclocal && autoconf && automake --add-missing
    ./configure
    make
    sudo make install
    ```

Contributing
------------

Feel free to make pull requests!

C coding style should follow the [Linux kernel Documentation/CodingStyle](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/CodingStyle?id=refs/heads/master).
