#!/usr/bin/env python
# vim: set fileencoding=utf-8
# vim: ts=4:sw=4:et:ai:sts=4
from distutils.core import setup, Extension

module1 = Extension('unshare', sources = ['unshare.c'])

setup(
        name        = 'Unshare',
        version     = '0.1',
        description = 'Python bindings for the Linux unshare() syscall',
        author      = 'Martin Ferrari',
        author_email = 'martin.ferrari@gmail.com',
        url         = 'http://code.google.com/p/python-unshare/',
        license     = 'GPLv2',
        ext_modules = [module1])
