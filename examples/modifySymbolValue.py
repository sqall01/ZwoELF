#!/usr/bin/python

from ctypes import c_uint
from ElfParserLib import ElfParser


x86File = "simple"
elfFile = ElfParser(x86File)
jmpRelEntry = elfFile.getJmpRelEntryByName("printf")
jmpRelEntry.symbol.st_value = 0x41414141
elfFile.writeElf("modified_simple")