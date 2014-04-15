#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# 
# Licensed under the GNU Public License, version 2.

from ctypes import c_uint
from ZwoELF import ElfParser


x86File = "simple"
elfFile = ElfParser(x86File)
jmpRelEntry = elfFile.getJmpRelEntryByName("printf")
jmpRelEntry.symbol.st_value = 0x41414141
elfFile.writeElf("modified_simple")