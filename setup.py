#!/bin/env python
# vim: set fileencoding=utf-8
from distutils.core import setup, Extension

module1 = Extension('unshare', sources = ['unshare.c'])

setup (name = 'Unshare',
       version = '0.1',
       description = 'Python bindings for the Linux unshare() syscall',
       author = 'Martin Ferrari',
       author_email = 'martin.ferrari@gmail.com',
       ext_modules = [module1])
