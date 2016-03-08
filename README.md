libiptc Go bindings
===================

[libiptc](http://www.tldp.org/HOWTO/Querying-libiptc-HOWTO/whatis.html) bindings for Go language.
Object-oriented design, support for IPv6 (libip6tc) and same wait locking mechanism as iptables/ip6tables official binaries.

This project currently contains preliminary code for Go bindings to libip4tc/libip6tc dynamic link libraries, most headers/commenst are from original [iptables](http://www.netfilter.org/) C headers.

Please note that there is no public/stable C/C++ API for libiptc, quoting from official [Netfilter FAQs](http://www.netfilter.org/documentation/FAQ/netfilter-faq-4.html#ss4.5):

> 4.5 Is there an C/C++ API for adding/removing rules?
> 
> The answer unfortunately is: No.
> 
> Now you might think 'but what about libiptc?'. As has been pointed out numerous times on the mailinglist(s), libiptc was _NEVER_ meant to be used as a public interface. We don't guarantee a stable interface, and it is planned to remove it in the next incarnation of linux packet filtering. libiptc is way too low-layer to be used reasonably anyway.
> 
> We are well aware that there is a fundamental lack for such an API, and we are working on improving that situation. Until then, it is recommended to either use system() or open a pipe into stdin of iptables-restore. The latter will give you a way better performance.
>

This Go package uses iptables headers; on Debian/Ubuntu systems they are provided by `iptables-dev` package.

TODO
====

* separate libip6tc package that uses '#cgo LDFLAGS: -lip6tc'
* unit tests coverage
* finally, some analysis of memory leakage

Interesting links
=================

* http://www.bani.com.br/2012/05/programmatically-managing-iptables-rules-in-c-iptc/

License
=======

Licensed under [GNU/GPL v2](LICENSE).
