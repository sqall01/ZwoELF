#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# github: https://github.com/sqall01
#
# Licensed under the GNU Public License, version 2.

from ctypes import c_uint
from ZwoELF import ElfParser
import sys


try:
	inputFile = sys.argv[1]
except:
	print('usage: {} <input file>'.format(sys.argv[0]))
	sys.exit(1)


test = ElfParser(inputFile)
test.printElf()
