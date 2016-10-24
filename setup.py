#!/usr/bin/env python
# vim: set fileencoding=utf-8
# vim: ts=4:sw=4:et:ai:sts=4
from distutils.core import setup, Extension

module1 = Extension('unshare', sources = ['unshare.c'])
longdesc = '''This simple extension provides bindings to the Linux unshare() syscall, added in kernel version 2.6.16

By using unshare(), new and interesting features of the Linux kernel can be exploited, such as:

* Creating a new network name space (CLONE_NEWNET)
* Creating a new file system mount name space (CLONE_NEWNS)
* Reverting other features shared from clone()'''

setup(
        name        = 'python-unshare',
        version     = '0.2',
        description = 'Python bindings for the Linux unshare() syscall',
        long_description = longdesc,
        author      = 'Martin Ferrari',
        author_email = 'martin.ferrari@gmail.com',
        url         = 'http://code.google.com/p/python-unshare/',
        license     = 'GPLv2',
        platforms   = 'Linux',
        ext_modules = [module1])
