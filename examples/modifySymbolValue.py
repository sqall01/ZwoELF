#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# github: https://github.com/sqall01
#
# Licensed under the GNU Public License, version 2.

import sys
from ctypes import c_uint
from ZwoELF import ElfParser

try:
	inputFile = sys.argv[1]
	outputFile = sys.argv[2]
except:
	print('usage: {} <input file> <output file>'.format(sys.argv[0]))
	sys.exit(1)


elfFile = ElfParser(inputFile)
jmpRelEntry = elfFile.getJmpRelEntryByName("strlen")
jmpRelEntry.symbol.ElfN_Sym.st_value = 0x41414141
elfFile.writeElf(outputFile)
