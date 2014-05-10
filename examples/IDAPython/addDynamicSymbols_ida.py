#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# github: https://github.com/sqall01
#
# Licensed under the GNU Public License, version 2.

from ZwoELF import ElfParser
from idautils import *

currentFile = GetInputFilePath()
elfFile = ElfParser(currentFile)

# rename all symbols from the jump entries in ida
for jmpRelEntry in elfFile.jumpRelocationEntries:
	name = jmpRelEntry.symbol.symbolName

	print "Add references for symbol: %s (0x%x)" % (name, jmpRelEntry.r_offset)
	MakeRptCmt(jmpRelEntry.r_offset, "%s (restored by script)" % name)
	dataRefs = DataRefsTo(jmpRelEntry.r_offset)

	# get address of the data reference (usually there is only one reference)
	address = list(dataRefs)[0]

	# rename address
	MakeName(address, name + "__restored")