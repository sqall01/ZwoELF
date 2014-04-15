#!/usr/bin/python

from ctypes import c_uint
from Zwoelf import ElfParser
import sys


x86File = sys.argv[1]


test = ElfParser(x86File)
test.printElf()
