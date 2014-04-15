#!/usr/bin/python

import sys
import os
from ctypes import c_uint
from ElfParserLib import ElfParser, SH_type, SH_flags
import random


# the added sections can be used to confuse analysis tools
# for example IDA 6.1.x tries to analyze all sections and it takes a 
# lot of time until the file is loaded
# (to circumvent this, just ignore sections and use segments)


testFile = ElfParser("x86_test_binaries/ls")


tempList = list(testFile.sections)
allowedSections = list()

for section in tempList:

	# IDA 6.1.x throws error when section uses ".dynsym" area: 
	# "Bad file structure or read error (line xxxx). Continue?"
	# and "Redeclared 'Dynamic symbol string table' section"
	# and "Relocation to non-code/data/bss section. Skip?"
	# and "Relocation to illegal symbol table. Skip?"

	# IDA 6.1.x throws error when section uses ".dynstr" area: 
	# "Bad file structure or read error (line xxxx). Continue?"
	# and "Redeclared 'Dynamic symbol string table' section"
	# and "Relocation to non-code/data/bss section. Skip?"

	# IDA 6.1.x throws error when section uses ".gnu.version_r" area: 
	# "Relocation to non-code/data/bss section. Skip?"

	# IDA 6.1.x throws error when section uses ".rel.dyn" area: 
	# "Relocation to non-code/data/bss section. Skip?"

	# IDA 6.1.x throws error when ".bss" section is used: "Can't read input
	# file (file structure error?), only part of file will be loaded..."

	# "readelf: Error: Invalid sh_entsize" when section lies within 
	# ".interp" section
	# "readelf: Error: Invalid sh_entsize" when section lies within 
	# ".note.ABI-tag" section
	# "readelf: Error: Invalid sh_entsize" when section lies within 
	# ".note.gnu.build-id" section
	# "readelf: Error: Invalid sh_entsize" when section lies within 
	# ".hash" section
	# "readelf: Error: Invalid sh_entsize" when section lies within 
	# ".gnu.hash" section

	if (section.sectionName == ".gnu.version"
		or section.sectionName == ".init"
		or section.sectionName == ".plt"
		or section.sectionName == ".fini"
		or section.sectionName == ".rodata"
		or section.sectionName == ".eh_frame_hdr"
		or section.sectionName == ".eh_frame"
		or section.sectionName == ".ctors"
		or section.sectionName == ".dtors"
		or section.sectionName == ".jcr"
		or section.sectionName == ".dynamic"
		or section.sectionName == ".got"
		or section.sectionName == ".got.plt"
		or section.sectionName == ".data"
		or section.sectionName == ".shstrtab"):
		
		# add section to list of sections in which new sections can 
		# be set without causing any errors
		allowedSections.append(section)


random.seed()

# add 10000 new random sections to obfuscate original sections
for count in range(10000):

	# calculate a random position within a random chosen section
	inSection = random.randint(0, len(allowedSections)-1)
	offset = allowedSections[inSection].elfN_shdr.sh_offset
	addr = allowedSections[inSection].elfN_shdr.sh_addr
	size = allowedSections[inSection].elfN_shdr.sh_size
	newStart = random.randint(0, size-1)
	offset += newStart
	addr += newStart
	size -= newStart

	# pick a random section name
	sectionName = random.randint(0, len(allowedSections)-1)
	newName = allowedSections[sectionName].sectionName

	# pick a random section name
	while True:
		sectionName = random.randint(0, len(allowedSections)-1)
		newName = allowedSections[sectionName].sectionName

		# ignore this section names because they can generate errors 
		# with IDA 6.1.x
		if (newName != ".got"
		and newName != ".got.plt"
		and newName != ".init"
		and newName != ".plt"
		and newName != ".fini"):
			break

	testFile.addNewSection(newName, SH_type.SHT_PROGBITS, 
		(SH_flags.SHF_EXECINSTR | SH_flags.SHF_ALLOC), addr, offset, 
		size, section.elfN_shdr.sh_link, section.elfN_shdr.sh_info, 
		section.elfN_shdr.sh_addralign, 0)


testFile.writeElf("test_ls")	