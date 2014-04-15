#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# 
# Licensed under the GNU Public License, version 2.

from ElfParserLib import ElfParser, Section, Segment
from Elf import ElfN_Ehdr, Shstrndx, Elf32_Shdr, SH_flags, SH_type, \
	Elf32_Phdr, P_type, P_flags, D_tag, ElfN_Dyn, ElfN_Rel, ElfN_Sym, R_type