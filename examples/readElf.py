#!/usr/bin/python

from ctypes import c_uint
from ElfParserLib import ElfParser


x86File = "ls"


test = ElfParser(x86File)
test.printElf()
