openfortivpn
============

Build from source
-----------------

```
aclocal && \
  autoconf && \
  automake --add-missing && \
  ./configure
make
sudo make install
```

Hacking
-------

# C coding style

C coding style should follow the [Linux kernel Documentation/CodingStyle](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/CodingStyle?id=refs/heads/master).
