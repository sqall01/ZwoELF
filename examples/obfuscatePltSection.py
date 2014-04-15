#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# 
# Licensed under the GNU Public License, version 2.

import sys
import os
from ctypes import c_uint
from ZwoELF import ElfParser, SH_type, SH_flags


# remove original ".got.plt" and ".plt" section and move them 
# to the ".text" section
# analysis tools like IDA 6.1.x and gdb try to read information 
# from this sections
# and show irritating informations, for example gdb shows plt 
# information when analyzing code in the .text section
# or calls to external functions are not resolved (even when IDA 6.1.x 
# uses segments instead of sections the
# external functions are not resolved)


testFile = ElfParser("x86_test_binaries/ls")

# remove ".got.plt" and ".plt" section
testFile.deleteSectionByName(".got.plt")
testFile.deleteSectionByName(".plt")

# copy section list to iterate on copied sections 
tempList = list(testFile.sections)

# iterate over sections
for section in tempList:

	# when ".text" section was found, create two new sections 
	# (".got.plt" and ".plt") with the same boundaries
	# this means that ".text", ".got.plt" and ".plt" overlap which 
	# confuses analysis tools like IDA 6.1.x and gdb
	if (section.sectionName == ".text"):
		testFile.addNewSection(".got.plt", SH_type.SHT_PROGBITS, 
			(SH_flags.SHF_EXECINSTR | SH_flags.SHF_ALLOC), 
			section.elfN_shdr.sh_addr, section.elfN_shdr.sh_offset, 
			section.elfN_shdr.sh_size, section.elfN_shdr.sh_link, 
			section.elfN_shdr.sh_info, section.elfN_shdr.sh_addralign, 0)
		testFile.addNewSection(".plt", SH_type.SHT_PROGBITS, 
			(SH_flags.SHF_EXECINSTR | SH_flags.SHF_ALLOC), 
			section.elfN_shdr.sh_addr, section.elfN_shdr.sh_offset, 
			section.elfN_shdr.sh_size, section.elfN_shdr.sh_link, 
			section.elfN_shdr.sh_info, section.elfN_shdr.sh_addralign, 0)
		break


testFile.writeElf("test_ls")
print "written to %s" % ("test_ls")		