#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# 
# Licensed under the GNU Public License, version 2.

from ctypes import c_uint
from ZwoELF import ElfParser
import sys


x86File = sys.argv[1]


test = ElfParser(x86File)
test.printElf()
