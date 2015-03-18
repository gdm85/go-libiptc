libiptc Go bindings
===================

[libiptc](http://www.tldp.org/HOWTO/Querying-libiptc-HOWTO/whatis.html) bindings for Go language.
Object-oriented design, support for IPv6 (libip6tc) and same wait locking mechanism as iptables/ip6tables official binaries.

This project currently contains preliminary code for Go bindings to libip4tc/libip6tc dynamic link libraries, most headers/commenst are from original [iptables](http://www.netfilter.org/) C headers.

TODO
====

* separate libip6tc package that uses '#cgo LDFLAGS: -lip6tc'
* unit tests coverage
* finally, some analysis of memory leakage

License
=======

Licensed under [GNU/GPL v2](LICENSE).
