#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# github: https://github.com/sqall01
# 
# Licensed under the GNU Public License, version 2.

import binascii
import sys
import hashlib
from Elf import ElfN_Ehdr, Shstrndx, Elf32_Shdr, SH_flags, SH_type, \
	Elf32_Phdr, P_type, P_flags, D_tag, ElfN_Dyn, ElfN_Rel, ElfN_Sym, R_type, \
	Section, Segment, DynamicSymbol


class ElfParser:

	def __init__(self, filename, force=False, startOffset=0, 
		forceDynSymParsing=0, onlyParseHeader=False):
		self.forceDynSymParsing = forceDynSymParsing
		self.header = None
		self.segments = list()
		self.sections = list()
		self.fileParsed = False
		self.dynamicSymbolEntries = list()
		self.dynamicSegmentEntries = list()
		self.jumpRelocationEntries = list()
		self.relocationEntries = list()
		self.startOffset = startOffset
		self.data = list()

		# read file and convert data to list
		f = open(filename, "rb")
		f.seek(self.startOffset, 0)
		self.data = list(f.read())
		f.close()

		# parse ELF file
		self.parseElf(self.data, onlyParseHeader=onlyParseHeader)

		# check if file was completely parsed
		if self.fileParsed is True:
			# generate md5 hash of file that was parsed
			tempHash = hashlib.md5()
			tempHash.update("".join(self.data))
			oldFileHash = tempHash.digest()

			# generate md5 hash of file that was newly generated
			tempHash = hashlib.md5()
			tempHash.update("".join(self.generateElf()))
			newFileHash = tempHash.digest()

			# check if parsed ELF file and new generated one are the same
			if oldFileHash != newFileHash and force is False:
				raise NotImplementedError('Not able to parse and ' \
					+ 're-generate ELF file correctly. This can happen '\
					+ 'when the ELF file is parsed out of an other file '\
					+ 'like a core dump. Use "force=True" to ignore this '\
					+ 'check.')


	# this function converts a section header entry to a list of data
	# return values: (list) converted section header entry
	def sectionHeaderEntryToList(self, sectionHeaderEntryToWrite):
		sectionHeaderEntryList = list()

		'''
		uint32_t   sh_name;
		'''
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_name & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_name >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_name >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_name >> 24) & 0xff))

		'''
		uint32_t   sh_type;
		'''
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_type & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_type >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_type >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_type >> 24) & 0xff))

		'''
		uint32_t   sh_flags;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_flags & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_flags >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_flags >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_flags >> 24) & 0xff))

		'''
		Elf32_Addr sh_addr;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_addr & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_addr >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_addr >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_addr >> 24) & 0xff))

		'''
		Elf32_Off  sh_offset;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_offset & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_offset >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_offset >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_offset >> 24) & 0xff))

		'''
		uint32_t   sh_size;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_size & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_size >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_size >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_size >> 24) & 0xff))

		'''
		uint32_t   sh_link;
		'''
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_link & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_link >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_link >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_link >> 24) & 0xff))

		'''
		uint32_t   sh_info;
		'''
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_info & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_info >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_info >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_info >> 24) & 0xff))

		'''
		uint32_t   sh_addralign;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_addralign & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_addralign >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_addralign >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_addralign >> 24) & 0xff))

		'''
		uint32_t   sh_entsize;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(
			chr(sectionHeaderEntryToWrite.sh_entsize & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_entsize >> 8) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_entsize >> 16) & 0xff))
		sectionHeaderEntryList.append(
			chr((sectionHeaderEntryToWrite.sh_entsize >> 24) & 0xff))

		return sectionHeaderEntryList


	# this function generates a new section
	# return values: (Section) new generated section
	def generateNewSection(self, sectionName, sh_name, sh_type, sh_flags,
		sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, 
		sh_entsize):
		newsection = Section()

		newsection.sectionName = sectionName

		'''
		uint32_t   sh_name;
		'''
		newsection.elfN_shdr.sh_name = sh_name

		'''
		uint32_t   sh_type;
		'''
		newsection.elfN_shdr.sh_type = sh_type

		'''
		uint32_t   sh_flags;
		'''
		# for 32 bit systems only
		newsection.elfN_shdr.sh_flags = sh_flags

		'''
		Elf32_Addr sh_addr;
		'''
		# for 32 bit systems only
		newsection.elfN_shdr.sh_addr = sh_addr

		'''
		Elf32_Off  sh_offset;
		'''
		# for 32 bit systems only
		newsection.elfN_shdr.sh_offset = sh_offset

		'''
		uint32_t   sh_size;
		'''
		# for 32 bit systems only
		newsection.elfN_shdr.sh_size = sh_size

		'''
		uint32_t   sh_link;
		'''
		newsection.elfN_shdr.sh_link = sh_link

		'''
		uint32_t   sh_info;
		'''
		newsection.elfN_shdr.sh_info = sh_info

		'''
		uint32_t   sh_addralign;
		'''
		# for 32 bit systems only
		newsection.elfN_shdr.sh_addralign = sh_addralign

		'''
		uint32_t   sh_entsize;
		'''
		# for 32 bit systems only
		newsection.elfN_shdr.sh_entsize = sh_entsize

		return newsection


	# this function parses a dynamic symbol at the given offset
	# return values: (DynamicSymbol) the parsed dynamic symbol
	def _parseDynamicSymbol(self, offset, stringTableOffset, stringTableSize):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		tempSymbol = DynamicSymbol()

		# get values from the symbol table
		'''
		Elf32_Word		st_name;
		'''
		# for 32 bit systems only
		tempSymbol.ElfN_Sym.st_name = \
			(ord(self.data[offset + 3]) \
			<< 24) \
			+ (ord(self.data[offset + 2]) \
			<< 16) \
			+ (ord(self.data[offset + 1]) \
			<< 8) \
			+ ord(self.data[offset])

		'''
		Elf32_Addr		st_value;
		'''
		# for 32 bit systems only
		tempSymbol.ElfN_Sym.st_value = \
			(ord(self.data[offset + 7]) \
			<< 24) + (ord(self.data[offset + 6]) \
			<< 16) + (ord(self.data[offset + 5]) \
			<< 8) + ord(self.data[offset + 4])

		'''
		Elf32_Word		st_size;
		'''
		# for 32 bit systems only
		tempSymbol.ElfN_Sym.st_size = \
			(ord(self.data[offset + 11]) << 24) \
			+ (ord(self.data[offset + 10]) << 16) \
			+ (ord(self.data[offset + 9]) << 8) \
			+ ord(self.data[offset + 8])

		'''
		unsigned char	st_info;
		'''
		# for 32 bit systems only
		tempSymbol.ElfN_Sym.st_info = ord(self.data[offset + 12])

		'''
		unsigned char	st_other;
		'''
		# for 32 bit systems only
		tempSymbol.ElfN_Sym.st_other = ord(self.data[offset + 13])

		'''
		Elf32_Half		st_shndx;
		'''
		# for 32 bit systems only
		tempSymbol.ElfN_Sym.st_shndx = \
			(ord(self.data[offset + 15]) \
			<< 8) \
			+ ord(self.data[offset + 14])

		# extract name from the string table
		temp = ""
		for i in range(
			(stringTableOffset + stringTableSize 
			- tempSymbol.ElfN_Sym.st_name)):
			if (self.data[stringTableOffset 
				+ tempSymbol.ElfN_Sym.st_name + i] == "\x00"):
				break
			temp += self.data[stringTableOffset \
				+ tempSymbol.ElfN_Sym.st_name + i]
		tempSymbol.symbolName = temp

		# return dynamic symbol
		return tempSymbol


	# this function parses the ELF file
	# return values: None
	def parseElf(self, buffer_list, onlyParseHeader=False):

		###############################################
		# parse ELF header

		'''
		The ELF header is described by the type Elf32_Ehdr or Elf64_Ehdr:

		#define EI_NIDENT 16

		typedef struct {
			unsigned char e_ident[EI_NIDENT];
			uint16_t      e_type;
			uint16_t      e_machine;
			uint32_t      e_version;
			ElfN_Addr     e_entry;
			ElfN_Off      e_phoff;
			ElfN_Off      e_shoff;
			uint32_t      e_flags;
			uint16_t      e_ehsize;
			uint16_t      e_phentsize;
			uint16_t      e_phnum;
			uint16_t      e_shentsize;
			uint16_t      e_shnum;
			uint16_t      e_shstrndx;
		} ElfN_Ehdr;
		'''


		self.header = ElfN_Ehdr()

		'''
		#define EI_NIDENT 16
		unsigned char e_ident[EI_NIDENT];
		'''
		for i in range(16):
			self.header.e_ident[i] = buffer_list[i]


		'''
		uint16_t      e_type;

		This member of the structure identifies the object file type.
		'''
		self.header.e_type = ord(buffer_list[17])*0x100 + ord(buffer_list[16])


		'''
		uint16_t      e_machine;

		This member specifies the required architecture for an individual file.
		'''
		self.header.e_machine = ord(buffer_list[19])*0x100 \
			+ ord(buffer_list[18])


		'''
		uint32_t      e_version;

		This member identifies the file version:

		EV_NONE     Invalid version.
		EV_CURRENT  Current version.
		'''
		self.header.e_version = ord(buffer_list[23])*0x1000000 \
			+ ord(buffer_list[22])*0x10000 + ord(buffer_list[21])*0x100 \
			+ ord(buffer_list[20])


		'''
		ElfN_Addr     e_entry;

		This member gives the virtual address to which the system first
		transfers control, thus starting the process. If the file has no
		associated entry point, this member holds zero.
		'''
		# for 32 bit systems only
		self.header.e_entry = ord(buffer_list[27])*0x1000000 \
			+ ord(buffer_list[26])*0x10000 + ord(buffer_list[25])*0x100 \
			+ ord(buffer_list[24])


		'''
		ElfN_Off      e_phoff;

		This  member holds the program header table's file offset in bytes.
		If the file has no program header table, this member holds zero.
		'''
		# for 32 bit systems only
		self.header.e_phoff = ord(buffer_list[31])*0x1000000 \
			+ ord(buffer_list[30])*0x10000 + ord(buffer_list[29])*0x100 \
			+ ord(buffer_list[28])


		'''
		ElfN_Off      e_shoff;

		This member holds the section header table's file offset in bytes 
		(from the beginning of the file).  If the file has no section header
		table this member holds zero.
		'''
		# for 32 bit systems only
		self.header.e_shoff = ord(buffer_list[35])*0x1000000 \
			+ ord(buffer_list[34])*0x10000 + ord(buffer_list[33])*0x100 \
			+ ord(buffer_list[32])


		'''
		uint32_t      e_flags;

		This member holds processor-specific flags associated with the file.
		Flag names take the form EF_`machine_flag'. Currently no flags have
		been defined.
		'''
		self.header.e_flags = ord(buffer_list[39])*0x1000000 \
			+ ord(buffer_list[38])*0x10000 + ord(buffer_list[37])*0x100 \
			+ ord(buffer_list[36])


		'''
		uint16_t      e_ehsize;

		This member holds the ELF header's size in bytes.
		'''
		self.header.e_ehsize = ord(buffer_list[41])*0x100 \
			+ ord(buffer_list[40])


		'''
		uint16_t      e_phentsize;

		This member holds the size in bytes of one entry in the file's 
		program header table; all entries are the same size.
		'''
		self.header.e_phentsize = ord(buffer_list[43])*0x100 \
			+ ord(buffer_list[42])


		'''
		uint16_t      e_phnum;

		This member holds the number of entries in the program header table.
		Thus the product of e_phentsize and e_phnum gives the table's size 
		in bytes. If a file has no program header, 
		e_phnum holds the value zero.

		If  the  number  of  entries in the program header table is 
		larger than or equal to PN_XNUM (0xffff), this member holds
		PN_XNUM (0xffff) and the real number of entries in the program 
		header table is held in the sh_info member of  the  initial
		entry in section header table.  Otherwise, the sh_info member of 
		the initial entry contains the value zero.

		PN_XNUM  This  is defined as 0xffff, the largest number e_phnum can
		have, specifying where the actual number of program headers 
		is assigned.
		'''
		self.header.e_phnum = ord(buffer_list[45])*0x100 + ord(buffer_list[44])


		'''
		uint16_t      e_shentsize;

		This member holds a sections header's size in bytes.  A section 
		header is one entry in the section  header  table;  all
		entries are the same size.
		'''
		self.header.e_shentsize = ord(buffer_list[47])*0x100 \
			+ ord(buffer_list[46])


		'''
		uint16_t      e_shnum;

		This member holds the number of entries in the section header table.
		Thus the product of e_shentsize and e_shnum gives the section 
		header table's size in bytes.  If a file has no section header table,
		e_shnum holds the value of zero.

		If the number of entries in the section header table is larger than or
		equal to SHN_LORESERVE (0xff00),  e_shnum  holds
		the  value zero and the real number of entries in the section 
		header table is held in the sh_size member of the initial		
		entry in section header table.  Otherwise, the sh_size member of 
		the initial entry in the section  header  table  holds
		the value zero.
		'''
		self.header.e_shnum = ord(buffer_list[49])*0x100 + ord(buffer_list[48])


		'''
		uint16_t      e_shstrndx;

		This  member  holds  the section header table index of the entry 
		associated with the section name string table.  If the
		file has no section name string table, this member holds 
		the value SHN_UNDEF.

		If the index of section name string table section is larger than 
		or equal to SHN_LORESERVE (0xff00), this member  holds
		SHN_XINDEX  (0xffff)  and  the real index of the section name 
		string table section is held in the sh_link member of the
		initial entry in section header table.  Otherwise, the sh_link 
		member of the initial entry in section header table contains 
		the value zero.
		'''
		self.header.e_shstrndx = ord(buffer_list[51])*0x100 \
			+ ord(buffer_list[50])


		###############################################
		# check if ELF is supported

		'''
		EI_MAG0     The first byte of the magic number. It must be 
			filled with ELFMAG0. (0x7f)
		EI_MAG1     The second byte of the magic number. It must be 
			filled with ELFMAG1. ('E')
		EI_MAG2     The third byte of the magic number. It must be 
			filled with ELFMAG2. ('L')
		EI_MAG3     The fourth byte of the magic number. It must be 
			filled with ELFMAG3. ('F')
		'''
		if not (self.header.e_ident[0] == chr(0x7f) 
			and self.header.e_ident[1] == 'E' 
			and self.header.e_ident[2] == 'L' 
			and self.header.e_ident[3] == 'F'):
			raise NotImplementedError("First 4 bytes do not have magic value")


		'''
		The fifth byte identifies the architecture for this binary
		'''
		if ord(self.header.e_ident[4]) == ElfN_Ehdr.EI_CLASS.ELFCLASSNONE:
			raise NotImplementedError("ELFCLASSNONE: This class is invalid.")
		elif ord(self.header.e_ident[4]) == ElfN_Ehdr.EI_CLASS.ELFCLASS64:
			raise NotImplementedError("ELFCLASS64: Not yet supported.")
		elif ord(self.header.e_ident[4]) != ElfN_Ehdr.EI_CLASS.ELFCLASS32:
			raise NotImplementedError("This class is invalid.")


		'''
		The sixth byte specifies the data encoding of the 
		processor-specific data in the file.
		'''
		if ord(self.header.e_ident[5]) == ElfN_Ehdr.EI_DATA.ELFDATANONE:
			raise NotImplementedError("ELFDATANONE: Unknown data format.")
		elif ord(self.header.e_ident[5]) == ElfN_Ehdr.EI_DATA.ELFDATA2MSB:
			raise NotImplementedError("ELFDATA2MSB: Not yet supported.")
		elif ord(self.header.e_ident[5]) != ElfN_Ehdr.EI_DATA.ELFDATA2LSB:
			raise NotImplementedError("Unknown data format.")


		'''
		The version number of the ELF specification
		'''
		if ord(self.header.e_ident[6]) == ElfN_Ehdr.EI_VERSION.EV_NONE:
			raise NotImplementedError("EV_NONE: Invalid version.")
		elif ord(self.header.e_ident[6]) != ElfN_Ehdr.EI_VERSION.EV_CURRENT:
			raise NotImplementedError("Invalid version.")


		'''
		This  byte  identifies  the operating system and ABI to which the
		object is targeted.  Some fields in other ELF structures have flags
		and values that have platform-specific  meanings;  the 
		interpretation  of  those fields is determined by the value of
		this byte.
		'''
		if not (ord(
			self.header.e_ident[7]) == ElfN_Ehdr.EI_OSABI.ELFOSABI_NONE
			or ord(
			self.header.e_ident[7]) == ElfN_Ehdr.EI_OSABI.ELFOSABI_LINUX):
			raise NotImplementedError("EI_OSABI not yet supported")


		'''
		This byte identifies the version of the ABI to which the object is
		targeted.  This field is used to distinguish among incompatible
		versions of an ABI.  The interpretation of this version number is
		dependent on the ABI identified by the EI_OSABI field. Applications
		conforming to this specification use the value 0.
		'''
		if ord(self.header.e_ident[8]) != 0:
			raise NotImplementedError("EI_ABIVERSION not yet supported")


		# check if e_type is supported at the moment
		if not (self.header.e_type == ElfN_Ehdr.E_type.ET_EXEC
			or self.header.e_type == ElfN_Ehdr.E_type.ET_DYN):
			raise NotImplementedError("Only e_type ET_EXEC and ET_DYN " \
				+ "are supported yet")


		# check if e_machine is supported at the moment
		if not (self.header.e_machine == ElfN_Ehdr.E_machine.EM_386):
			raise NotImplementedError("Only e_machine EM_386 is supported yet")


		# check if only the header of the ELF file should be parsed
		# for example to speed up the process for checking if a list of files
		# are valid ELF files
		if onlyParseHeader is True:
			return

		# mark file as completely parsed (actually it is just parsing
		# but without this flag internal functions will not work)
		self.fileParsed = True


		###############################################
		# parse section header table

		'''
		The section header has the following structure:

		typedef struct {
			uint32_t   sh_name;
			uint32_t   sh_type;
			uint32_t   sh_flags;
			Elf32_Addr sh_addr;
			Elf32_Off  sh_offset;
			uint32_t   sh_size;
			uint32_t   sh_link;
			uint32_t   sh_info;
			uint32_t   sh_addralign;
			uint32_t   sh_entsize;
		} Elf32_Shdr;

		typedef struct {
			uint32_t   sh_name;
			uint32_t   sh_type;
			uint64_t   sh_flags;
			Elf64_Addr sh_addr;
			Elf64_Off  sh_offset;
			uint64_t   sh_size;
			uint32_t   sh_link;
			uint32_t   sh_info;
			uint64_t   sh_addralign;
			uint64_t   sh_entsize;
		} Elf64_Shdr;
		'''

		# create a list of the section_header_table
		self.sections = list()

		for i in range(self.header.e_shnum):
			tempSectionEntry = Elf32_Shdr()

			'''
			uint32_t   sh_name;

			This member specifies the name of the section.  Its value is an
			index into the section header string table section,  giving the
			location of a null-terminated string.
			'''
			tempSectionEntry.sh_name = ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 3])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 2])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 1])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 0])

			'''
			uint32_t   sh_type;

			This member categorizes the section's contents and semantics.
			'''
			tempSectionEntry.sh_type = ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 7])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 6])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 5])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 4])

			'''
			uint32_t   sh_flags;

			Sections support one-bit flags that describe miscellaneous
			attributes.  If a flag bit is set in sh_flags,  the  attribute
			is "on" for the section.  Otherwise, the attribute is "off" or
			does not apply.  Undefined attributes are set to zero.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_flags = ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 11])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 10])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 9])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 8])

			'''
			Elf32_Addr sh_addr;

			If this section appears in the memory image of a process, this
			member holds the address at which the section's first byte
			should reside.  Otherwise, the member contains zero.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_addr = ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 15])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 14])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 13])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 12])

			'''
			Elf32_Off  sh_offset;

			This  member's  value holds the byte offset from the beginning 
			of the file to the first byte in the section.  One section
			type, SHT_NOBITS, occupies no space in the file, and its 
			sh_offset member locates the conceptual placement in the file.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_offset = ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 19])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 18])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 17])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 16])

			'''
			uint32_t   sh_size;

			This member holds the section's size in bytes.  Unless the section
			type is SHT_NOBITS, the section occupies sh_size bytes
			in the file.  A section of type SHT_NOBITS may have a nonzero
			size, but it occupies no space in the file.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_size = ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 23])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 22])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 21])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 20])

			'''
			uint32_t   sh_link;

			This member holds a section header table index link, whose 
			interpretation depends on the section type.
			'''
			tempSectionEntry.sh_link = ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 27])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 26])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 25])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 24])

			'''
			uint32_t   sh_info;

			This member holds extra information, whose interpretation 
			depends on the section type.
			'''
			tempSectionEntry.sh_info = ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 31])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 30])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 29])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 28])

			'''
			uint32_t   sh_addralign;

			Some  sections  have  address  alignment constraints.  If a 
			section holds a doubleword, the system must ensure doubleword
			alignment for the entire section.  That is, the value of  sh_addr
			must  be  congruent  to  zero,  modulo  the  value  of
			sh_addralign.   Only zero and positive integral powers of two 
			are allowed.  Values of zero or one mean the section has no
			alignment constraints.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_addralign = \
				ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 35])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 34])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 33])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 32])

			'''
			uint32_t   sh_entsize;

			Some sections hold a table of fixed-sized entries, such as a 
			symbol table.  For such a section,  this  member  gives  the
			size in bytes for each entry.  This member contains zero if 
			the section does not hold a table of fixed-size entries.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_entsize = ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 39])*0x1000000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 38])*0x10000 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 37])*0x100 \
				+ ord(buffer_list[self.header.e_shoff \
				+ i*self.header.e_shentsize + 36])

			# create new section and add to sections list
			section = Section()
			section.elfN_shdr = tempSectionEntry
			self.sections.append(section)


		###############################################
		# parse section string table

		# section string table first byte always 0 byte
		# section string table last byte always 0 byte
		# section string table holds null terminated strings
		# empty section string table => sh_size of string table section = 0 
		# => Non-zero indexes to string table are invalid

		# check if sections exists => read whole string table
		if self.sections != list():
			stringtable_str = ""
			for i in range(
				self.sections[self.header.e_shstrndx].elfN_shdr.sh_size):
				stringtable_str += \
					buffer_list[self.sections[self.header.e_shstrndx].elfN_shdr.sh_offset + i]

			# get name from string table for each section
			for i in range(len(self.sections)):

				# check if string table exists => abort reading
				if len(stringtable_str) == 0:
					break

				tempName = ""
				counter = self.sections[i].elfN_shdr.sh_name
				while (ord(stringtable_str[counter]) != 0 
					and counter < len(stringtable_str)):
					tempName += stringtable_str[counter]
					counter += 1
				self.sections[i].sectionName = tempName


		###############################################
		# parse program header table

		'''
		typedef struct {
			uint32_t   p_type;
			Elf32_Off  p_offset;
			Elf32_Addr p_vaddr;
			Elf32_Addr p_paddr;
			uint32_t   p_filesz;
			uint32_t   p_memsz;
			uint32_t   p_flags;
			uint32_t   p_align;
		} Elf32_Phdr;

		typedef struct {
			uint32_t   p_type;
			uint32_t   p_flags;
			Elf64_Off  p_offset;
			Elf64_Addr p_vaddr;
			Elf64_Addr p_paddr;
			uint64_t   p_filesz;
			uint64_t   p_memsz;
			uint64_t   p_align;
		} Elf64_Phdr;
		'''

		# create a list of the program_header_table
		self.segments = list()

		for i in range(self.header.e_phnum):

			tempSegment = Segment()

			'''
			uint32_t   p_type;

			This  member  of  the Phdr struct tells what kind of segment 
			this array element describes or how to interpret the array
			element's information.
			'''
			tempSegment.elfN_Phdr.p_type = \
				ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 3])*0x1000000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 2])*0x10000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 1])*0x100 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 0])

			'''
			Elf32_Off  p_offset;

			This member holds the offset from the beginning of the 
			file at which the first byte of the segment resides.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_offset = \
				ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 7])*0x1000000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 6])*0x10000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 5])*0x100 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 4])

			'''
			Elf32_Addr p_vaddr;

			This member holds the virtual address at which the first 
			byte of the segment resides in memory.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_vaddr = \
				ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 11])*0x1000000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 10])*0x10000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 9])*0x100 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 8])

			'''
			Elf32_Addr p_paddr;

			On  systems  for  which  physical  addressing  is relevant, this
			member is reserved for the segment's physical address.
			Under BSD this member is not used and must be zero.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_paddr = \
				ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 15])*0x1000000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 14])*0x10000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 13])*0x100 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 12])

			'''
			uint32_t   p_filesz;

			This member holds the number of bytes in the file image of 
			the segment.  It may be zero.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_filesz = \
				ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 19])*0x1000000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 18])*0x10000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 17])*0x100 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 16])

			'''
			uint32_t   p_memsz;

			This member holds the number of bytes in the memory image 
			of the segment.  It may be zero.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_memsz = \
				ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 23])*0x1000000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 22])*0x10000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 21])*0x100 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 20])

			'''
			uint32_t   p_flags;

			This member holds a bitmask of flags relevant to the segment:

			PF_X   An executable segment.
			PF_W   A writable segment.
			PF_R   A readable segment.

			A text segment commonly has the flags PF_X and PF_R.  
			A data segment commonly has PF_X, PF_W and PF_R.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_flags = \
				ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 27])*0x1000000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 26])*0x10000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 25])*0x100 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 24])

			'''
			uint32_t   p_align;

			This member holds the value to which the segments are aligned 
			in memory and in the  file.   Loadable  process  segments
			must have congruent values for p_vaddr and p_offset, modulo 
			the page size.  Values of zero and one mean no alignment is
			required.  Otherwise, p_align should be a positive, integral 
			power of two, and p_vaddr should  equal  p_offset,  modulo
			p_align.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_align = \
				ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 31])*0x1000000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 30])*0x10000 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 29])*0x100 \
				+ ord(buffer_list[self.header.e_phoff \
				+ i*self.header.e_phentsize + 28])

			# check which sections are in the current segment 
			# (in memory) and add them
			for section in self.sections:
				if (section.elfN_shdr.sh_addr >= tempSegment.elfN_Phdr.p_vaddr
					and (section.elfN_shdr.sh_addr + section.elfN_shdr.sh_size)
					<= (tempSegment.elfN_Phdr.p_vaddr + 
					tempSegment.elfN_Phdr.p_memsz)):
					tempSegment.sectionsWithin.append(section)

			self.segments.append(tempSegment)


		# get all segments within a segment
		for outerSegment in self.segments:
			for segmentWithin in self.segments:

				# skip if segments are the same
				if segmentWithin == outerSegment:
					continue

				# check if segmentWithin lies within the outerSegment
				if (segmentWithin.elfN_Phdr.p_offset 
					> outerSegment.elfN_Phdr.p_offset
					and (segmentWithin.elfN_Phdr.p_offset 
					+ segmentWithin.elfN_Phdr.p_filesz) 
					< (outerSegment.elfN_Phdr.p_offset 
					+ outerSegment.elfN_Phdr.p_filesz)):
						outerSegment.segmentsWithin.append(segmentWithin)


		###############################################
		# parse dynamic segment entries

		'''
		typedef struct {
			Elf32_Sword    d_tag;
			union {
				Elf32_Word d_val;
				Elf32_Addr d_ptr;
			} d_un;
		} Elf32_Dyn;

		typedef struct {
			Elf64_Sxword    d_tag;
			union {
				Elf64_Xword d_val;
				Elf64_Addr  d_ptr;
			} d_un;
		} Elf64_Dyn;
		'''

		# find dynamic segment
		dynamicSegment = None
		for segment in self.segments:
			if segment.elfN_Phdr.p_type == P_type.PT_DYNAMIC:
				dynamicSegment = segment
				break
		if dynamicSegment is None:
			raise ValueError("Segment of type PT_DYNAMIC was not found.")

		# create a list for all dynamic segment entries
		self.dynamicSegmentEntries = list()

		# for 32 bit systems only
		endReached = False
		for i in range((dynamicSegment.elfN_Phdr.p_filesz / 8)):

			# parse dynamic segment entry
			dynSegmentEntry = ElfN_Dyn()

			'''
			Elf32_Sword d_tag;
			'''
			# for 32 bit systems only
			dynSegmentEntry.d_tag = \
				(ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 3 + i*8]) \
				<< 24) \
				+ (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 2 \
				+ i*8]) << 16) \
				+ (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 1 \
				+ i*8]) << 8) \
				+ ord(self.data[dynamicSegment.elfN_Phdr.p_offset + i*8])

			'''
			union {
				Elf32_Sword d_val;
				Elf32_Addr  d_ptr;
			} d_un
			'''
			# for 32 bit systems only
			dynSegmentEntry.d_un = \
				(ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 7 + i*8]) \
				<< 24) \
				+ (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 6 + \
				i*8]) << 16) \
				+ (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 5 + \
				i*8]) << 8) \
				+ ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 4 + i*8])

			# add dynamic segment entry to list
			self.dynamicSegmentEntries.append(dynSegmentEntry)

			# check if the end of the dynamic segment array is reached
			if dynSegmentEntry.d_tag == D_tag.DT_NULL:
				endReached = True
				break

		# check if end was reached with PT_NULL entry
		if not endReached:
			raise ValueError("PT_NULL was not found in segment of type" \
			+ "PT_DYNAMIC (malformed ELF executable/shared object).")


		###############################################
		# parse relocation entries


		# search for relocation entries in dynamic segment entries
		jmpRelOffset = None
		pltRelSize = None
		pltRelType = None
		relEntrySize = None
		relOffset = None		
		relSize = None
		symbolEntrySize = None
		symbolTableOffset = None
		stringTableOffset = None
		stringTableSize = None
		for dynEntry in self.dynamicSegmentEntries:
			if dynEntry.d_tag == D_tag.DT_JMPREL:
				# get the offset in the file of the jump relocation table
				jmpRelOffset = self.virtualMemoryAddrToFileOffset(
					dynEntry.d_un)
				continue
			if dynEntry.d_tag == D_tag.DT_PLTRELSZ:
				pltRelSize = dynEntry.d_un
				continue
			if dynEntry.d_tag == D_tag.DT_PLTREL:
				pltRelType = dynEntry.d_un
				continue
			if dynEntry.d_tag == D_tag.DT_RELENT:
				relEntrySize = dynEntry.d_un
				continue
			if dynEntry.d_tag == D_tag.DT_REL:
				# get the offset in the file of the relocation table
				relOffset = self.virtualMemoryAddrToFileOffset(dynEntry.d_un)
				continue
			if dynEntry.d_tag == D_tag.DT_RELSZ:
				relSize = dynEntry.d_un
				continue
			if dynEntry.d_tag == D_tag.DT_SYMENT:
				symbolEntrySize = dynEntry.d_un
				continue
			if dynEntry.d_tag == D_tag.DT_SYMTAB:
				# get the offset in the file of the symbol table
				symbolTableOffset = self.virtualMemoryAddrToFileOffset(
					dynEntry.d_un)
				continue
			if dynEntry.d_tag == D_tag.DT_STRTAB:
				# get the offset in the file of the string table
				stringTableOffset = self.virtualMemoryAddrToFileOffset(
					dynEntry.d_un)
				continue
			if dynEntry.d_tag == D_tag.DT_STRSZ:
				stringTableSize = dynEntry.d_un


		# check if ELF got needed entries
		if (stringTableOffset is None
			or stringTableSize is None
			or symbolTableOffset is None
			or symbolEntrySize is None):
			raise ValueError("No dynamic section entry of type DT_STRTAB," \
				" DT_STRSZ, DT_SYMTAB and/or DT_SYMENT found (malformed ELF" \
				" executable/shared object).")


		# estimate symbol table size in order to not rely on sections
		# when ELF is compiled with gcc, the .dynstr section (string table)
		# follows directly the .dynsym section (symbol table)
		# => size of symbol table is difference between string and symbol table
		estimatedSymbolTableSize = stringTableOffset - symbolTableOffset

		# find .dynsym section in sections
		# and only use if it exists once
		dynSymSection = None
		dynSymSectionDuplicated = False
		dynSymSectionIgnore = False
		dynSymEstimationIgnore = False
		for section in self.sections:
			if section.sectionName == ".dynsym":
				# check if .dynsym section only exists once
				# (because section entries are optional and can
				# be easily manipulated)
				if dynSymSection is None:
					dynSymSection = section

				# when .dynsym section exists multiple times
				# do not use it
				else:
					dynSymSectionDuplicated = True
					break

		# check if .dynsym section exists
		if dynSymSection is None:
			print 'NOTE: ".dynsym" section was not found. Trying to use ' \
				+ 'estimation to parse all symbols from the symbol table'
			dynSymSectionIgnore = True

		# check if .dynsym section was found multiple times
		elif dynSymSectionDuplicated is True:
			print 'NOTE: ".dynsym" section was found multiple times. ' \
				+ 'Trying to use estimation to parse all symbols from' \
				+ 'the symbol table'
			dynSymSectionIgnore = True		

		# check if symbol table offset matches the offset of the
		# ".dynsym" section
		elif dynSymSection.elfN_shdr.sh_offset != symbolTableOffset:
			print 'NOTE: ".dynsym" section offset does not match ' \
				+ 'offset of symbol table. Ignoring the section ' \
				+ 'and using the estimation.'
			dynSymSectionIgnore = True

		# check if the size of the ".dynsym" section matches the
		# estimated size
		elif dynSymSection.elfN_shdr.sh_size != estimatedSymbolTableSize:

			# check if forceDynSymParsing was not set (default value is 0)
			if self.forceDynSymParsing == 0:
				print 'WARNING: ".dynsym" size does not match the estimated ' \
					+ 'size. One (or both) are wrong. Ignoring the dynamic ' \
					+ ' symbols. You can force the using of the ".dynsym" ' \
					+ 'section by setting "forceDynSymParsing=1" or force ' \
					+ 'the using of the estimated size by setting ' \
					+ '"forceDynSymParsing=2".'

				# ignore dynamic symbols
				dynSymSectionIgnore = True
				dynSymEstimationIgnore = True

			# forcing the use of the ".dynsym" section
			elif self.forceDynSymParsing == 1:

				dynSymSectionIgnore = False
				dynSymEstimationIgnore = True

			# forcing the use of the estimation
			elif self.forceDynSymParsing == 2:

				dynSymSectionIgnore = True
				dynSymEstimationIgnore = False

			# value does not exists
			else:
				raise TypeError('"forceDynSymParsing" uses an invalid value.')

		# use ".dynsym" section information (when considered correct)
		if dynSymSectionIgnore is False:

			# parse the complete symbol table based on the
			# ".dynsym" section
			for i in range(dynSymSection.elfN_shdr.sh_size \
				/ symbolEntrySize):

				tempOffset = symbolTableOffset + (i*symbolEntrySize)
				tempSymbol = self._parseDynamicSymbol(tempOffset,
					stringTableOffset, stringTableSize)

				# add entry to dynamic symbol entries list
				self.dynamicSymbolEntries.append(tempSymbol)

		# use estimation to parse dynamic symbols
		elif (dynSymSectionIgnore is True
			and dynSymEstimationIgnore is False):

			# parse the complete symbol table based on the
			# estimation
			for i in range(estimatedSymbolTableSize \
				/ symbolEntrySize):

				tempOffset = symbolTableOffset + (i*symbolEntrySize)
				tempSymbol = self._parseDynamicSymbol(tempOffset,
					stringTableOffset, stringTableSize)

				# add entry to dynamic symbol entries list
				self.dynamicSymbolEntries.append(tempSymbol)


		# check if DT_JMPREL entry exists (it is optional for ELF
		# executables/shared objects)
		# => parse jump relocation entries
		if jmpRelOffset is not None:

			# create a list for all jump relocation entries
			self.jumpRelocationEntries = list()

			# parse all jump relocation entries
			for i in range(pltRelSize / relEntrySize):
				jmpRelEntry = ElfN_Rel()
				'''
				Elf32_Addr    r_offset;
				'''
				# in executable and share object files 
				# => r_offset holds a virtual address
				# for 32 bit systems only
				jmpRelEntry.r_offset = \
					(ord(self.data[jmpRelOffset + (i*relEntrySize) + 3]) \
					<< 24) \
					+ (ord(self.data[jmpRelOffset + (i*relEntrySize) + 2]) \
					<< 16) \
					+ (ord(self.data[jmpRelOffset + (i*relEntrySize) + 1]) \
					<< 8) + ord(self.data[jmpRelOffset + (i*relEntrySize)])

				'''
				Elf32_Word    r_info;
				'''
				# for 32 bit systems only
				jmpRelEntry.r_info = \
					(ord(self.data[jmpRelOffset + (i*relEntrySize) + 7]) \
					<< 24) \
					+ (ord(self.data[jmpRelOffset + (i*relEntrySize) + 6]) \
					<< 16) \
					+ (ord(self.data[jmpRelOffset + (i*relEntrySize) + 5]) \
					<< 8) \
					+ ord(self.data[jmpRelOffset + (i*relEntrySize) + 4])

				# for 32 bit systems only
				# calculated: "(unsigned char)r_info" or just "r_info & 0xFF"
				jmpRelEntry.r_type = (jmpRelEntry.r_info & 0xFF)

				# for 32 bit systems only
				# calculated: "r_info >> 8"
				jmpRelEntry.r_sym = (jmpRelEntry.r_info >> 8)

				# get values from the symbol table
				tempOffset = symbolTableOffset \
					+ (jmpRelEntry.r_sym*symbolEntrySize)
				tempSymbol = self._parseDynamicSymbol(tempOffset,
					stringTableOffset, stringTableSize)

				# check if parsed dynamic symbol already exists
				# if it does => use already existed dynamic symbol
				# else => use newly parsed dynamic symbol
				dynamicSymbolFound = False
				for dynamicSymbol in self.dynamicSymbolEntries:
					if (tempSymbol.ElfN_Sym.st_name
						== dynamicSymbol.ElfN_Sym.st_name
						and tempSymbol.ElfN_Sym.st_value
						== dynamicSymbol.ElfN_Sym.st_value
						and tempSymbol.ElfN_Sym.st_size
						== dynamicSymbol.ElfN_Sym.st_size
						and tempSymbol.ElfN_Sym.st_info
						== dynamicSymbol.ElfN_Sym.st_info
						and tempSymbol.ElfN_Sym.st_other
						== dynamicSymbol.ElfN_Sym.st_other
						and tempSymbol.ElfN_Sym.st_shndx
						== dynamicSymbol.ElfN_Sym.st_shndx):
						jmpRelEntry.symbol = dynamicSymbol
						dynamicSymbolFound = True
						break
				if dynamicSymbolFound is False:
					jmpRelEntry.symbol = tempSymbol

				# add entry to jump relocation entries list
				self.jumpRelocationEntries.append(jmpRelEntry)


		# check if DT_REL entry exists (DT_REL is only 
		# mandatory when DT_RELA is not present)
		# => parse relocation entries
		if relOffset is not None:

			# create a list for all relocation entries
			self.relocationEntries = list()

			# parse all relocation entries
			for i in range(relSize / relEntrySize):
				relEntry = ElfN_Rel()
				'''
				Elf32_Addr    r_offset;
				'''
				# in executable and share object files 
				# => r_offset holds a virtual address
				# for 32 bit systems only
				relEntry.r_offset = \
					(ord(self.data[relOffset + (i*relEntrySize) + 3]) \
					<< 24) \
					+ (ord(self.data[relOffset + (i*relEntrySize) + 2]) \
					<< 16) \
					+ (ord(self.data[relOffset + (i*relEntrySize) + 1]) \
					<< 8) \
					+ ord(self.data[relOffset + (i*relEntrySize)])

				'''
				Elf32_Word    r_info;
				'''
				# for 32 bit systems only
				relEntry.r_info = \
					(ord(self.data[relOffset + (i*relEntrySize) + 7]) \
					<< 24) \
					+ (ord(self.data[relOffset + (i*relEntrySize) + 6]) \
					<< 16) \
					+ (ord(self.data[relOffset + (i*relEntrySize) + 5]) \
					<< 8) \
					+ ord(self.data[relOffset + (i*relEntrySize) + 4])

				# for 32 bit systems only
				# calculated: "(unsigned char)r_info" or just "r_info & 0xFF"
				relEntry.r_type = (relEntry.r_info & 0xFF)

				# for 32 bit systems only
				# calculated: "r_info >> 8"
				relEntry.r_sym = (relEntry.r_info >> 8)	

				# get values from the symbol table
				tempOffset = symbolTableOffset \
					+ (relEntry.r_sym*symbolEntrySize)
				tempSymbol = self._parseDynamicSymbol(tempOffset,
					stringTableOffset, stringTableSize)

				# check if parsed dynamic symbol already exists
				# if it does => use already existed dynamic symbol
				# else => use newly parsed dynamic symbol
				dynamicSymbolFound = False
				for dynamicSymbol in self.dynamicSymbolEntries:
					if (tempSymbol.ElfN_Sym.st_name
						== dynamicSymbol.ElfN_Sym.st_name
						and tempSymbol.ElfN_Sym.st_value
						== dynamicSymbol.ElfN_Sym.st_value
						and tempSymbol.ElfN_Sym.st_size
						== dynamicSymbol.ElfN_Sym.st_size
						and tempSymbol.ElfN_Sym.st_info
						== dynamicSymbol.ElfN_Sym.st_info
						and tempSymbol.ElfN_Sym.st_other
						== dynamicSymbol.ElfN_Sym.st_other
						and tempSymbol.ElfN_Sym.st_shndx
						== dynamicSymbol.ElfN_Sym.st_shndx):
						relEntry.symbol = dynamicSymbol
						dynamicSymbolFound = True
						break
				if dynamicSymbolFound is False:
					relEntry.symbol = tempSymbol

				# add entry to relocation entries list
				self.relocationEntries.append(relEntry)


	# this function outputs the parsed ELF file (like readelf)
	# return values: None
	def printElf(self):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# output header
		print "ELF header:"
		print "Type: %s" % ElfN_Ehdr.E_type.reverse_lookup[self.header.e_type]
		print "Version: %s" \
			% ElfN_Ehdr.EI_VERSION.reverse_lookup[ord(self.header.e_ident[6])]
		print "Machine: %s" \
			% ElfN_Ehdr.E_machine.reverse_lookup[self.header.e_machine]
		print "Entry point address: 0x%x" % self.header.e_entry
		print "Program header table offset in bytes: 0x%x (%d)" \
			% (self.header.e_phoff, self.header.e_phoff)
		print "Section header table offset in bytes: 0x%x (%d)" \
			% (self.header.e_shoff, self.header.e_shoff)
		print "Flags: 0x%x (%d)" % (self.header.e_flags, self.header.e_flags)
		print "Size of ELF header in bytes: 0x%x (%d)" \
			% (self.header.e_ehsize, self.header.e_ehsize)
		print "Size of each program header entry in bytes: 0x%x (%d)" \
			% (self.header.e_phentsize, self.header.e_phentsize)
		print "Number of program header entries: %d" % self.header.e_phnum
		print "Size of each sections header entry in bytes: 0x%x (%d)" \
			% (self.header.e_shentsize, self.header.e_shentsize)
		print "Number of section header entries: %d" % self.header.e_shnum
		print "Section header string table index: %d" % self.header.e_shstrndx
		print


		# output of all sections
		counter = 0
		for section in self.sections:
			print "Section No. %d" % counter
			print "Name: %s" % section.sectionName

			# translate type
			if section.elfN_shdr.sh_type in SH_type.reverse_lookup.keys():
				print "Type: %s" \
					% SH_type.reverse_lookup[section.elfN_shdr.sh_type]
			else:
				print "Unknown Type: 0x%x (%d)" \
					% (section.elfN_shdr.sh_type, section.elfN_shdr.sh_type)

			print "Addr: 0x%x" % section.elfN_shdr.sh_addr
			print "Off: 0x%x" % section.elfN_shdr.sh_offset
			print "Size: 0x%x (%d)" \
				% (section.elfN_shdr.sh_size, section.elfN_shdr.sh_size)
			print "ES: %d" % section.elfN_shdr.sh_entsize

			# translate flags
			temp = ""
			if (section.elfN_shdr.sh_flags & SH_flags.SHF_WRITE) != 0:
				temp += "W"
			if (section.elfN_shdr.sh_flags & SH_flags.SHF_ALLOC) != 0:
				temp += "A"
			if (section.elfN_shdr.sh_flags & SH_flags.SHF_EXECINSTR) != 0:
				temp += "X"

			print "FLG: %s" % temp
			print "Lk: %d" % section.elfN_shdr.sh_link
			print "Inf: %d" % section.elfN_shdr.sh_info
			print "Al: %d" % section.elfN_shdr.sh_addralign
			print
			counter += 1


		# output of all segments
		counter = 0
		for segment in self.segments:
			print "Segment No. %d" % counter

			# translate type
			if segment.elfN_Phdr.p_type in P_type.reverse_lookup.keys():
				print "Type: %s" \
					% P_type.reverse_lookup[segment.elfN_Phdr.p_type]
			else:
				print "Unknown Type: 0x%x (%d)" \
					% (segment.elfN_Phdr.p_type, segment.elfN_Phdr.p_type)

			print "Offset: 0x%x" % segment.elfN_Phdr.p_offset
			print "Virtual Addr: 0x%x" % segment.elfN_Phdr.p_vaddr
			print "Physical Addr: 0x%x" % segment.elfN_Phdr.p_paddr
			print "File Size: 0x%x (%d)" \
				% (segment.elfN_Phdr.p_filesz, segment.elfN_Phdr.p_filesz)
			print "Mem Size: 0x%x (%d)" \
				% (segment.elfN_Phdr.p_memsz, segment.elfN_Phdr.p_memsz)

			# translate flags
			temp = ""
			if (segment.elfN_Phdr.p_flags & P_flags.PF_R) != 0:
				temp += "R"
			if (segment.elfN_Phdr.p_flags & P_flags.PF_W) != 0:
				temp += "W"
			if (segment.elfN_Phdr.p_flags & P_flags.PF_X) != 0:
				temp += "X"
			print "Flags: %s" % temp

			print "Align: 0x%x" % segment.elfN_Phdr.p_align

			# print which sections are in the current segment (in memory)
			temp = ""
			for section in segment.sectionsWithin:
					temp += section.sectionName + " "
			if temp != "":
				print "Sections in segment: " + temp

			# print which segments are within current segment (in file)
			temp = ""
			for segmentWithin in segment.segmentsWithin:
				for i in range(len(self.segments)):
					if segmentWithin == self.segments[i]:
						temp += "%d, " % i
						break
			if temp != "":
				print "Segments within segment: " + temp

			# get interpreter if segment is for interpreter 
			# null-terminated string
			if segment.elfN_Phdr.p_type == P_type.PT_INTERP:
				temp = ""
				for i in range(segment.elfN_Phdr.p_filesz):
					temp += self.data[segment.elfN_Phdr.p_offset + i]
				print "Interpreter: %s" % temp

			print 
			counter += 1


		# search string table entry, string table size, 
		# symbol table entry and symbol table entry size
		stringTableOffset = None
		stringTableSize = None
		symbolTableOffset = None
		symbolEntrySize = None
		for searchEntry in self.dynamicSegmentEntries:
			if searchEntry.d_tag == D_tag.DT_STRTAB:
				# data contains virtual memory address 
				# => calculate offset in file
				stringTableOffset = \
					self.virtualMemoryAddrToFileOffset(searchEntry.d_un)
			if searchEntry.d_tag == D_tag.DT_STRSZ:
				stringTableSize = searchEntry.d_un
			if searchEntry.d_tag == D_tag.DT_SYMTAB:
				# data contains virtual memory address 
				# => calculate offset in file
				symbolTableOffset = \
					self.virtualMemoryAddrToFileOffset(searchEntry.d_un)
			if searchEntry.d_tag == D_tag.DT_SYMENT:
				symbolEntrySize = searchEntry.d_un

		if (stringTableOffset is None
			or stringTableSize is None
			or symbolTableOffset is None
			or symbolEntrySize is None):
			raise ValueError("No dynamic section entry of type DT_STRTAB," \
				+ " DT_STRSZ, DT_SYMTAB and/or DT_SYMENT found (malformed"\
				+ " ELF executable/shared object).")


		# output all dynamic segment entries
		counter = 0
		for entry in self.dynamicSegmentEntries:
			print "Dynamic segment entry No. %d" % counter
			if entry.d_tag in D_tag.reverse_lookup.keys():
				print "Type: %s" % D_tag.reverse_lookup[entry.d_tag]
			else:
				print "Unknwon Type: 0x%x (%d)" % (entry.d_tag, entry.d_tag)

			# check if entry tag equals DT_NEEDED => get library name
			if entry.d_tag == D_tag.DT_NEEDED:
				temp = ""
				for i in range(
					(stringTableOffset + stringTableSize - entry.d_un)):
					if self.data[stringTableOffset + entry.d_un + i] == "\x00":
						break
					temp += self.data[stringTableOffset + entry.d_un + i]
				print "Name/Value: 0x%x (%d) (%s)" \
					% (entry.d_un, entry.d_un, temp)
			else:
				print "Name/Value: 0x%x (%d)" % (entry.d_un, entry.d_un)

			print
			counter += 1


		# output all jump relocation entries
		print("Jump relocation entries (%d entries)" \
			% len(self.jumpRelocationEntries))
		print("No."),
		print("\t"),
		print("MemAddr"),
		print("\t"),
		print("File offset"),
		print("\t"),
		print("Info"),
		print("\t\t"),
		print("Type"),
		print("\t\t"),
		print("Sym. value"),
		print("\t"),
		print("Sym. name"),
		print
		print("\t"),
		print("(r_offset)"),
		print("\t"),
		print("\t"),
		print("\t"),
		print("(r_info)"),
		print("\t"),
		print("(r_type)"),
		print

		counter = 0
		for entry in self.jumpRelocationEntries:
			symbol = entry.symbol.ElfN_Sym
			print("%d" % counter),
			print("\t"),
			print("0x" + ("%x" % entry.r_offset).zfill(8)),
			print("\t"),

			# try to convert the virtual memory address to a file offset
			# in executable and share object files 
			# => r_offset holds a virtual address			
			try:
				print("0x" + ("%x" \
					% self.virtualMemoryAddrToFileOffset(
					entry.r_offset)).zfill(8)),
			except:
				print("None\t"),			

			print("\t"),
			print("0x" + ("%x" % entry.r_info).zfill(8)),
			print("\t"),

			# translate type
			if entry.r_type in R_type.reverse_lookup.keys():
				print("%s" % R_type.reverse_lookup[entry.r_type]), 
			else:
				print("0x%x" % entry.r_type),			

			print("\t"),
			print("0x" + ("%x" % symbol.st_value).zfill(8)),

			print("\t"),
			print(entry.symbol.symbolName),

			print

			counter += 1

		print

		# output all relocation entries
		print("Relocation entries (%d entries)" % len(self.relocationEntries))
		print("No."),
		print("\t"),
		print("MemAddr"),
		print("\t"),
		print("File offset"),
		print("\t"),
		print("Info"),
		print("\t\t"),
		print("Type"),
		print("\t\t"),
		print("Sym. value"),
		print("\t"),
		print("Sym. name"),
		print
		print("\t"),
		print("(r_offset)"),
		print("\t"),
		print("\t"),
		print("\t"),
		print("(r_info)"),
		print("\t"),
		print("(r_type)"),
		print

		counter = 0
		for entry in self.relocationEntries:
			symbol = entry.symbol.ElfN_Sym
			print("%d" % counter),
			print("\t"),
			print("0x" + ("%x" % entry.r_offset).zfill(8)),
			print("\t"),

			# try to convert the virtual memory address to a file offset
			# in executable and share object files 
			# => r_offset holds a virtual address			
			try:
				print("0x" + ("%x" \
					% self.virtualMemoryAddrToFileOffset(
					entry.r_offset)).zfill(8)),
			except:
				print("None\t"),			

			print("\t"),
			print("0x" + ("%x" % entry.r_info).zfill(8)),
			print("\t"),

			# translate type
			if entry.r_type in R_type.reverse_lookup.keys():
				print("%s" % R_type.reverse_lookup[entry.r_type]), 
			else:
				print("0x%x" % entry.r_type),			

			print("\t"),
			print("0x" + ("%x" % symbol.st_value).zfill(8)),

			print("\t"),
			print(entry.symbol.symbolName),

			print
			counter += 1

		print			

		# output all dynamic symbol entries
		print("Dynamic symbols (%d entries)" % len(self.dynamicSymbolEntries))
		print("No."),
		print("\t"),
		print("Value"),
		print("\t\t"),
		print("Size"),
		print("\t"),
		print("Name"),
		print

		counter = 0
		for entry in self.dynamicSymbolEntries:
			symbol = entry.ElfN_Sym
			print("%d" % counter),
			print("\t"),
			print("0x" + ("%x" % symbol.st_value).zfill(8)),
			print("\t"),
			print("0x" + ("%x" % symbol.st_size).zfill(3)),
			print("\t"),
			print("%s" % entry.symbolName),

			print
			counter += 1			


	# this function generates a new ELF file from the attributes of the object
	# return values: (list) generated ELF file data
	def generateElf(self):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# copy binary data to new list
		newfile = list(self.data)

		# ------

		# get position of section header table
		writePosition = self.header.e_shoff

		# fill list with null until writePosition is reached
		while writePosition > len(newfile):
			newfile.append("\x00")

		# write section header table back
		for section in self.sections:
			temp = self.sectionHeaderEntryToList(section.elfN_shdr)
			for i in range(len(temp)):
				# as long as writePosition is not larger or equal to 
				# the length of the newfile list
				# => overwrite old data
				# if it is => append data
				if writePosition < len(newfile):
					newfile[writePosition] = temp[i]
				else:
					newfile.append(temp[i])	

				writePosition += 1

		# ------

		# when defined => write string table back
		if self.header.e_shstrndx != Shstrndx.SHN_UNDEF:
			for section in self.sections:
				# calculate the position on which the name should be written
				writePosition = \
					self.sections[self.header.e_shstrndx].elfN_shdr.sh_offset \
					+ section.elfN_shdr.sh_name

				# fill list with null until writePosition is reached
				while writePosition > len(newfile):
					newfile.append("\x00")

				# write name of all sections into string table
				for i in range(len(section.sectionName)):
					# as long as writePosition is not larger 
					# or equal to the length of the newfile list
					# => overwrite old data
					# if it is => append data
					if writePosition < len(newfile):
						newfile[writePosition] = section.sectionName[i]
					else:
						newfile.append(section.sectionName[i])			
					writePosition += 1

				# append null byte (all written strings are null-terminated)
				if writePosition < len(newfile):
					newfile[writePosition] = "\x00"
				else:
					newfile.append("\x00")			

		# ------

		# write ELF header back
		for i in range(len(self.header.e_ident)):
			if i < len(newfile):
				newfile[i] = self.header.e_ident[i]
			else:
				newfile.append(self.header.e_ident[i])


		'''
		uint16_t      e_type;
		'''
		newfile[16] = (chr(self.header.e_type & 0xff))
		newfile[17] = (chr((self.header.e_type >> 8) & 0xff))

		'''
		uint16_t      e_machine;
		'''
		newfile[18] = (chr(self.header.e_machine & 0xff))
		newfile[19] = (chr((self.header.e_machine >> 8) & 0xff))

		'''
		uint32_t      e_version;
		'''
		newfile[20] = (chr(self.header.e_version & 0xff))
		newfile[21] = (chr((self.header.e_version >> 8) & 0xff))
		newfile[22] = (chr((self.header.e_version >> 16) & 0xff))
		newfile[23] = (chr((self.header.e_version >> 24) & 0xff))

		'''
		ElfN_Addr     e_entry;
		'''
		# for 32 bit systems only
		newfile[24] = (chr(self.header.e_entry & 0xff))
		newfile[25] = (chr((self.header.e_entry >> 8) & 0xff))
		newfile[26] = (chr((self.header.e_entry >> 16) & 0xff))
		newfile[27] = (chr((self.header.e_entry >> 24) & 0xff))

		'''
		ElfN_Off      e_phoff;
		'''
		# for 32 bit systems only
		newfile[28] = (chr(self.header.e_phoff & 0xff))
		newfile[29] = (chr((self.header.e_phoff >> 8) & 0xff))
		newfile[30] = (chr((self.header.e_phoff >> 16) & 0xff))
		newfile[31] = (chr((self.header.e_phoff >> 24) & 0xff))

		'''
		ElfN_Off      e_shoff;
		'''
		# for 32 bit systems only
		newfile[32] = (chr(self.header.e_shoff & 0xff))
		newfile[33] = (chr((self.header.e_shoff >> 8) & 0xff))
		newfile[34] = (chr((self.header.e_shoff >> 16) & 0xff))
		newfile[35] = (chr((self.header.e_shoff >> 24) & 0xff))

		'''
		uint32_t      e_flags;
		'''
		newfile[36] = (chr(self.header.e_flags & 0xff))
		newfile[37] = (chr((self.header.e_flags >> 8) & 0xff))
		newfile[38] = (chr((self.header.e_flags >> 16) & 0xff))
		newfile[39] = (chr((self.header.e_flags >> 24) & 0xff))

		'''
		uint16_t      e_ehsize;
		'''
		newfile[40] = (chr(self.header.e_ehsize & 0xff))
		newfile[41] = (chr((self.header.e_ehsize >> 8) & 0xff))

		'''
		uint16_t      e_phentsize;
		'''
		newfile[42] = (chr(self.header.e_phentsize & 0xff))
		newfile[43] = (chr((self.header.e_phentsize >> 8) & 0xff))

		'''
		uint16_t      e_phnum;
		'''
		newfile[44] = (chr(self.header.e_phnum & 0xff))
		newfile[45] = (chr((self.header.e_phnum >> 8) & 0xff))

		'''
		uint16_t      e_shentsize;
		'''
		newfile[46] = (chr(self.header.e_shentsize & 0xff))
		newfile[47] = (chr((self.header.e_shentsize >> 8) & 0xff))

		'''
		uint16_t      e_shnum;
		'''
		newfile[48] = (chr(self.header.e_shnum & 0xff))
		newfile[49] = (chr((self.header.e_shnum >> 8) & 0xff))

		'''
		uint16_t      e_shstrndx;
		'''
		newfile[50] = (chr(self.header.e_shstrndx & 0xff))
		newfile[51] = (chr((self.header.e_shstrndx >> 8) & 0xff))

		# ------

		# write programm header table back
		for i in range(len(self.segments)):

			# add placeholder bytes to new file when the bytes do not already
			# exist in the new file until size of header entry fits
			while (self.header.e_phoff + (i*self.header.e_phentsize) 
				+ self.header.e_phentsize) > len(newfile):
				newfile.append("\x00")

			'''
			uint32_t   p_type;
			'''
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 0] \
				= (chr(self.segments[i].elfN_Phdr.p_type & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 1] \
				= (chr((self.segments[i].elfN_Phdr.p_type >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 2] \
				= (chr((self.segments[i].elfN_Phdr.p_type >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 3] \
				= (chr((self.segments[i].elfN_Phdr.p_type >> 24) & 0xff))

			'''
			Elf32_Off  p_offset;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 4] \
				= (chr(self.segments[i].elfN_Phdr.p_offset & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 5] \
				= (chr((self.segments[i].elfN_Phdr.p_offset >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 6] \
				= (chr((self.segments[i].elfN_Phdr.p_offset >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 7] \
				= (chr((self.segments[i].elfN_Phdr.p_offset >> 24) & 0xff))

			'''
			Elf32_Addr p_vaddr;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 8] \
				= (chr(self.segments[i].elfN_Phdr.p_vaddr & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 9] \
				= (chr((self.segments[i].elfN_Phdr.p_vaddr >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 10] \
				= (chr((self.segments[i].elfN_Phdr.p_vaddr >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 11] \
				= (chr((self.segments[i].elfN_Phdr.p_vaddr >> 24) & 0xff))

			'''
			Elf32_Addr p_paddr;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 12] \
				= (chr(self.segments[i].elfN_Phdr.p_paddr & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 13] \
				= (chr((self.segments[i].elfN_Phdr.p_paddr >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 14] \
				= (chr((self.segments[i].elfN_Phdr.p_paddr >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 15] \
				= (chr((self.segments[i].elfN_Phdr.p_paddr >> 24) & 0xff))

			'''
			uint32_t   p_filesz;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 16] \
				= (chr(self.segments[i].elfN_Phdr.p_filesz & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 17] \
				= (chr((self.segments[i].elfN_Phdr.p_filesz >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 18] \
				= (chr((self.segments[i].elfN_Phdr.p_filesz >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 19] \
				= (chr((self.segments[i].elfN_Phdr.p_filesz >> 24) & 0xff))

			'''
			uint32_t   p_memsz;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 20] \
				= (chr(self.segments[i].elfN_Phdr.p_memsz & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 21] \
				= (chr((self.segments[i].elfN_Phdr.p_memsz >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 22] \
				= (chr((self.segments[i].elfN_Phdr.p_memsz >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 23] \
				= (chr((self.segments[i].elfN_Phdr.p_memsz >> 24) & 0xff))

			'''
			uint32_t   p_flags;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 24] \
				= (chr(self.segments[i].elfN_Phdr.p_flags & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 25] \
				= (chr((self.segments[i].elfN_Phdr.p_flags >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 26] \
				= (chr((self.segments[i].elfN_Phdr.p_flags >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 27] \
				= (chr((self.segments[i].elfN_Phdr.p_flags >> 24) & 0xff))

			'''
			uint32_t   p_align;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 28] \
				= (chr(self.segments[i].elfN_Phdr.p_align & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 29] \
				= (chr((self.segments[i].elfN_Phdr.p_align >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 30] \
				= (chr((self.segments[i].elfN_Phdr.p_align >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 31] \
				= (chr((self.segments[i].elfN_Phdr.p_align >> 24) & 0xff))

		# ------

		# find dynamic segment
		dynamicSegment = None
		for segment in self.segments:
			if segment.elfN_Phdr.p_type == P_type.PT_DYNAMIC:
				dynamicSegment = segment
				break
		if dynamicSegment is None:
			raise ValueError("Segment of type PT_DYNAMIC was not found.")

		# write all dynamic segment entries back
		for i in range(len(self.dynamicSegmentEntries)):

			'''
			Elf32_Sword    d_tag;
			'''
			# for 32 bit systems only
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 0] \
				= (chr(self.dynamicSegmentEntries[i].d_tag & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 1] \
				= (chr((self.dynamicSegmentEntries[i].d_tag >> 8) & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 2] \
				= (chr((self.dynamicSegmentEntries[i].d_tag >> 16) & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 3] \
				= (chr((self.dynamicSegmentEntries[i].d_tag >> 24) & 0xff))

			'''
			union {
				Elf32_Word d_val;
				Elf32_Addr d_ptr;
			} d_un;
			'''
			# for 32 bit systems only
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 4] \
				= (chr(self.dynamicSegmentEntries[i].d_un & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 5] \
				= (chr((self.dynamicSegmentEntries[i].d_un >> 8) & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 6] \
				= (chr((self.dynamicSegmentEntries[i].d_un >> 16) & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 7] \
				= (chr((self.dynamicSegmentEntries[i].d_un >> 24) & 0xff))

		# overwrite rest of segment with 0x00 (default padding data)
		# (NOTE: works in all test cases, but can cause md5 parsing 
		# check to fail!)
		# for 32 bit systems only
		for i in range(dynamicSegment.elfN_Phdr.p_filesz 
			- (len(self.dynamicSegmentEntries)*8)):
			newfile[dynamicSegment.elfN_Phdr.p_offset \
				+ (len(self.dynamicSegmentEntries)*8) + i] = "\x00"

		# ------

		# search for relocation entries in dynamic segment entries
		jmpRelOffset = None
		pltRelSize = None
		relEntrySize = None
		relOffset = None		
		relSize = None
		symbolTableOffset = None
		symbolEntrySize = None		
		for dynEntry in self.dynamicSegmentEntries:
			if dynEntry.d_tag == D_tag.DT_JMPREL:
				# get the offset in the file of the jump relocation table
				jmpRelOffset = self.virtualMemoryAddrToFileOffset(
					dynEntry.d_un)
				continue
			if dynEntry.d_tag == D_tag.DT_PLTRELSZ:
				pltRelSize = dynEntry.d_un
				continue
			if dynEntry.d_tag == D_tag.DT_RELENT:
				relEntrySize = dynEntry.d_un
				continue
			if dynEntry.d_tag == D_tag.DT_REL:
				# get the offset in the file of the relocation table
				relOffset = self.virtualMemoryAddrToFileOffset(dynEntry.d_un)
				continue
			if dynEntry.d_tag == D_tag.DT_SYMTAB:
				# get the offset in the file of the symbol table
				symbolTableOffset = self.virtualMemoryAddrToFileOffset(
					dynEntry.d_un)
				continue
			if dynEntry.d_tag == D_tag.DT_SYMENT:
				symbolEntrySize = dynEntry.d_un
				continue				
			if dynEntry.d_tag == D_tag.DT_RELSZ:
				relSize = dynEntry.d_un


		# write dynamic symbols back to dynamic symbol table
		# (if the dynamic symbol table could be parsed)
		for i in range(len(self.dynamicSymbolEntries)):

			if symbolTableOffset is not None:
				dynSymEntry = self.dynamicSymbolEntries[i]
				symbol = dynSymEntry.ElfN_Sym

				'''
				Elf32_Word		st_name;
				'''
				# for 32 bit systems only
				newfile[symbolTableOffset \
				+ (i * symbolEntrySize) + 0] \
					= (chr((symbol.st_name >> 0) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 1] \
					= (chr((symbol.st_name >> 8) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 2] \
					= (chr((symbol.st_name >> 16) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 3] \
					= (chr((symbol.st_name >> 24) & 0xff))
				'''
				Elf32_Addr		st_value;
				'''
				# for 32 bit systems only
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 4] \
					= (chr((symbol.st_value >> 0) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 5] \
					= (chr((symbol.st_value >> 8) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 6] \
					= (chr((symbol.st_value >> 16) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 7] \
					= (chr((symbol.st_value >> 24) & 0xff))	

				'''
				Elf32_Word		st_size;
				'''
				# for 32 bit systems only
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 8] \
					= (chr((symbol.st_size >> 0) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 9] \
					= (chr((symbol.st_size >> 8) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 10] \
					= (chr((symbol.st_size >> 16) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 11] \
					= (chr((symbol.st_size >> 24) & 0xff))

				'''
				unsigned char	st_info;
				'''
				# for 32 bit systems only
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 12] \
					= (chr((symbol.st_info) & 0xff))

				'''
				unsigned char	st_other;
				'''
				# for 32 bit systems only
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 13] \
					= (chr((symbol.st_other) & 0xff))

				'''
				Elf32_Half		st_shndx;
				'''
				# for 32 bit systems only
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 14] \
					= (chr((symbol.st_shndx >> 0) & 0xff))
				newfile[symbolTableOffset \
					+ (i * symbolEntrySize) + 15] \
					= (chr((symbol.st_shndx >> 8) & 0xff))	


		# check if DT_JMPREL entry exists (it is optional 
		# for ELF executables/shared objects)
		# => write jump relocation entries back
		if jmpRelOffset is not None:
			for i in range(len(self.jumpRelocationEntries)):
				'''
				Elf32_Addr    r_offset;
				'''
				# for 32 bit systems only
				newfile[jmpRelOffset + (i*relEntrySize) + 0] \
					= (chr(self.jumpRelocationEntries[i].r_offset & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 1] \
					= (chr((self.jumpRelocationEntries[i].r_offset \
					>> 8) & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 2] \
					= (chr((self.jumpRelocationEntries[i].r_offset \
					>> 16) & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 3] \
					= (chr((self.jumpRelocationEntries[i].r_offset \
					>> 24) & 0xff))

				'''
				Elf32_Word    r_info;
				'''
				# for 32 bit systems only
				newfile[jmpRelOffset + (i*relEntrySize) + 4] \
					= (chr(self.jumpRelocationEntries[i].r_info & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 5] \
					= (chr((self.jumpRelocationEntries[i].r_info \
					>> 8) & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 6] \
					= (chr((self.jumpRelocationEntries[i].r_info \
					>> 16) & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 7] \
					= (chr((self.jumpRelocationEntries[i].r_info \
					>> 24) & 0xff))

				# check if dynamic symbol was already written
				# when writing all dynamic symbol entries back
				# if not => write dynamic symbol back
				jmpRelEntry = self.jumpRelocationEntries[i]
				dynSym = jmpRelEntry.symbol				
				if (dynSym not in self.dynamicSymbolEntries
					and symbolTableOffset is not None):

					symbol = dynSym.ElfN_Sym

					'''
					Elf32_Word		st_name;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 0] \
						= (chr((symbol.st_name >> 0) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 1] \
						= (chr((symbol.st_name >> 8) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 2] \
						= (chr((symbol.st_name >> 16) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 3] \
						= (chr((symbol.st_name >> 24) & 0xff))

					'''
					Elf32_Addr		st_value;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 4] \
						= (chr((symbol.st_value >> 0) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 5] \
						= (chr((symbol.st_value >> 8) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 6] \
						= (chr((symbol.st_value >> 16) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 7] \
						= (chr((symbol.st_value >> 24) & 0xff))	

					'''
					Elf32_Word		st_size;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 8] \
						= (chr((symbol.st_size >> 0) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 9] \
						= (chr((symbol.st_size >> 8) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 10] \
						= (chr((symbol.st_size >> 16) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 11] \
						= (chr((symbol.st_size >> 24) & 0xff))

					'''
					unsigned char	st_info;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 12] \
						= (chr((symbol.st_info) & 0xff))

					'''
					unsigned char	st_other;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 13] \
						= (chr((symbol.st_other) & 0xff))

					'''
					Elf32_Half		st_shndx;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 14] \
						= (chr((symbol.st_shndx >> 0) & 0xff))
					newfile[symbolTableOffset \
						+ (jmpRelEntry.r_sym * symbolEntrySize) + 15] \
						= (chr((symbol.st_shndx >> 8) & 0xff))	


		# check if DT_REL entry exists (DT_REL is only mandatory 
		# when DT_RELA is not present)
		# => write relocation entries back
		if relOffset is not None:
			for i in range(len(self.relocationEntries)):
				'''
				Elf32_Addr    r_offset;
				'''
				# for 32 bit systems only
				newfile[relOffset + (i*relEntrySize) + 0] \
					= (chr(self.relocationEntries[i].r_offset & 0xff))
				newfile[relOffset + (i*relEntrySize) + 1] \
					= (chr((self.relocationEntries[i].r_offset >> 8) & 0xff))
				newfile[relOffset + (i*relEntrySize) + 2] \
					= (chr((self.relocationEntries[i].r_offset >> 16) & 0xff))
				newfile[relOffset + (i*relEntrySize) + 3] \
					= (chr((self.relocationEntries[i].r_offset >> 24) & 0xff))

				'''
				Elf32_Word    r_info;
				'''
				# for 32 bit systems only
				newfile[relOffset + (i*relEntrySize) + 4] \
					= (chr(self.relocationEntries[i].r_info & 0xff))
				newfile[relOffset + (i*relEntrySize) + 5] \
					= (chr((self.relocationEntries[i].r_info >> 8) & 0xff))
				newfile[relOffset + (i*relEntrySize) + 6] \
					= (chr((self.relocationEntries[i].r_info >> 16) & 0xff))
				newfile[relOffset + (i*relEntrySize) + 7] \
					= (chr((self.relocationEntries[i].r_info >> 24) & 0xff))

				# check if dynamic symbol was already written
				# when writing all dynamic symbol entries back
				# if not => write dynamic symbol back
				relEntry = self.relocationEntries[i]
				dynSym = relEntry.symbol				
				if (dynSym not in self.dynamicSymbolEntries
					and symbolTableOffset is not None):

					symbol = dynSym.ElfN_Sym

					'''
					Elf32_Word		st_name;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 0] \
						= (chr((symbol.st_name >> 0) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 1] \
						= (chr((symbol.st_name >> 8) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 2] \
						= (chr((symbol.st_name >> 16) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 3] \
						= (chr((symbol.st_name >> 24) & 0xff))

					'''
					Elf32_Addr		st_value;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 4] \
						= (chr((symbol.st_value >> 0) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 5] \
						= (chr((symbol.st_value >> 8) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 6] \
						= (chr((symbol.st_value >> 16) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 7] \
						= (chr((symbol.st_value >> 24) & 0xff))	

					'''
					Elf32_Word		st_size;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 8] \
						= (chr((symbol.st_size >> 0) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 9] \
						= (chr((symbol.st_size >> 8) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 10] \
						= (chr((symbol.st_size >> 16) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 11] \
						= (chr((symbol.st_size >> 24) & 0xff))

					'''
					unsigned char	st_info;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 12] \
						= (chr((symbol.st_info) & 0xff))

					'''
					unsigned char	st_other;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 13] \
						= (chr((symbol.st_other) & 0xff))

					'''
					Elf32_Half		st_shndx;
					'''
					# for 32 bit systems only
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 14] \
						= (chr((symbol.st_shndx >> 0) & 0xff))
					newfile[symbolTableOffset \
						+ (relEntry.r_sym * symbolEntrySize) + 15] \
						= (chr((symbol.st_shndx >> 8) & 0xff))	

		# ------

		return newfile


	# this function writes the generated ELF file back
	# return values: None
	def writeElf(self, filename):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		f = open(filename, "w")
		f.write("".join(self.generateElf()))
		f.close()


	# this function appends data to a selected segment number (if it fits)
	# return values: (int) offset in file of appended data, 
	# (int) address in memory of appended data
	def appendDataToSegment(self, data, segmentNumber, addNewSection=False,
		newSectionName=None, extendExistingSection=False):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		segmentToExtend = self.segments[segmentNumber]

		# find segment that comes directly after the segment 
		# to manipulate in the virtual memory
		nextSegment, diff_p_vaddr \
			= self.getNextSegmentAndFreeSpace(segmentToExtend)

		# check if a segment exists directly after the segment 
		# to manipulate in the virtual memory
		if nextSegment is None:
			# segment directly after segment to 
			# manipulate does not exist in virtual memory

			# get memory address and offset in file of appended data
			newDataMemoryAddr = segmentToExtend.elfN_Phdr.p_vaddr \
				+ segmentToExtend.elfN_Phdr.p_memsz
			newDataOffset = segmentToExtend.elfN_Phdr.p_offset \
				+ segmentToExtend.elfN_Phdr.p_filesz

			# insert data
			for i in range(len(data)):
				self.data.insert((newDataOffset + i), data[i])

			# adjust offsets of all following section 
			# (for example symbol sections are often behind all segments)
			for section in self.sections:
				if (section.elfN_shdr.sh_offset >= 
					(segmentToExtend.elfN_Phdr.p_offset 
					+ segmentToExtend.elfN_Phdr.p_filesz)):
					section.elfN_shdr.sh_offset += len(data)

			# extend size of data in file of the modifed segment
			segmentToExtend.elfN_Phdr.p_filesz += len(data)

			# extend size of data in memory of the modifed segment
			segmentToExtend.elfN_Phdr.p_memsz += len(data)					


		else: 
			# segment directly after segment to 
			# manipulate exists in virtual memory

			# check if data to append fits
			if len(data) >= diff_p_vaddr:
				raise ValueError("Size of data to append: %d " \
					+ "Size of memory space: %d" % (len(data), diff_p_vaddr))

			# p_offset and p_vaddr are congruend modulo alignment
			# for example:
			# p_align: 0x1000 (default for LOAD segment)
			# p_offset: 0x016f88
			# p_vaddr: 0x0805ff88
			# => 0x016f88 % 0x1000 = 0xf88
			# both must have 0xf88 at the end of the address

			# get how often the appended data fits in the 
			# alignment of the segment
			alignmentMultiplier = int(len(data) \
				/ segmentToExtend.elfN_Phdr.p_align) + 1

			# calculate the size to add to the offsets
			offsetAddition = alignmentMultiplier \
				* segmentToExtend.elfN_Phdr.p_align 

			# adjust offsets of all following section
			for section in self.sections:
				if (section.elfN_shdr.sh_offset 
					>= nextSegment.elfN_Phdr.p_offset):
					section.elfN_shdr.sh_offset += offsetAddition

			# adjust offsets of following segments 
			# (ignore the directly followed segment)
			for segment in self.segments:
				if segment != segmentToExtend and segment != nextSegment:
					# use offset of the directly followed segment in order to
					# ignore segments that lies within the 
					# segment to manipulate
					if (segment.elfN_Phdr.p_offset 
						> nextSegment.elfN_Phdr.p_offset):
						segment.elfN_Phdr.p_offset += offsetAddition

			# adjust offset of the directly following segment of the 
			# segment to manipulate
			nextSegment.elfN_Phdr.p_offset += offsetAddition

			# if program header table lies behind the segment to manipulate 
			# => move it
			if (self.header.e_phoff > (segmentToExtend.elfN_Phdr.p_offset 
				+ segmentToExtend.elfN_Phdr.p_filesz)):
				self.header.e_phoff += offsetAddition

			# if section header table lies behind the segment to manipulate 
			# => move it
			if (self.header.e_shoff > (segmentToExtend.elfN_Phdr.p_offset 
				+ segmentToExtend.elfN_Phdr.p_filesz)):
				self.header.e_shoff += offsetAddition

			# get memory address and offset in file of appended data
			newDataMemoryAddr = segmentToExtend.elfN_Phdr.p_vaddr \
				+ segmentToExtend.elfN_Phdr.p_memsz
			newDataOffset = segmentToExtend.elfN_Phdr.p_offset \
				+ segmentToExtend.elfN_Phdr.p_filesz	

			# insert data
			for i in range(len(data)):
				self.data.insert((newDataOffset + i), data[i])

			# fill the rest with 0x00 until the offset addition in the 
			# file is reached
			for i in range((offsetAddition - len(data))):
				self.data.insert((newDataOffset + len(data) + i), "\x00")

			# extend size of data in file of the modifed segment
			segmentToExtend.elfN_Phdr.p_filesz += len(data)

			# extend size of data in memory of the modifed segment
			segmentToExtend.elfN_Phdr.p_memsz += len(data)


		# if added data should have an own section => add new section
		if addNewSection and not extendExistingSection:

			# calculate alignment of new section
			# start with 16 as alignment (is used by .text section)
			newSectionAddrAlign = 16
			while newSectionAddrAlign != 1:
				if (len(data) % newSectionAddrAlign) == 0:
					break
				else:
					newSectionAddrAlign = newSectionAddrAlign / 2

			# add section
			# addNewSection(newSectionName, newSectionType, newSectionFlag,
			# newSectionAddr, newSectionOffset, newSectionSize, 
			# newSectionLink, newSectionInfo, newSectionAddrAlign, 
			# newSectionEntsize)
			self.addNewSection(newSectionName, SH_type.SHT_PROGBITS, 
				(SH_flags.SHF_EXECINSTR | SH_flags.SHF_ALLOC), 
				newDataMemoryAddr, newDataOffset, len(data), 0, 0, 
				newSectionAddrAlign, 0)

		# if added data should extend an existing section 
		# => search this section and extend it
		if extendExistingSection and not addNewSection:
			for section in self.sections:
				# the end of an existing section in the virtual 
				# memory is generally equal
				# to the virtual memory address of the added data
				if ((section.elfN_shdr.sh_addr + section.elfN_shdr.sh_size) 
					== newDataMemoryAddr):
					# check if data is not appended to last section 
					# => use free space between segments for section 
					if diff_p_vaddr is not None:
						# extend the existing section
						self.extendSection(section, diff_p_vaddr)
					else:
						# extend the existing section
						self.extendSection(section, len(data))

					break

		if not extendExistingSection and not addNewSection:
			print "NOTE: if appended data do not belong to a section they " \
				+ "will not be seen by tools that interpret sections " \
				+ "(like 'IDA 6.1.x' without the correct settings or " \
				+ "'strings' in the default configuration)."

		# return offset of appended data in file and address in memory
		return newDataOffset, newDataMemoryAddr


	# this function generates and adds a new section to the ELF file
	# return values: None
	def addNewSection(self, newSectionName, newSectionType, newSectionFlag, 
		newSectionAddr, newSectionOffset, newSectionSize, newSectionLink, 
		newSectionInfo, newSectionAddrAlign, newSectionEntsize):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# check if sections do not exist
		# => create new section header table
		if len(self.sections) == 0:

			# restore section header entry size
			# for 32 bit systems only
			self.header.e_shentsize = 40

			# when using gcc, first section is NULL section
			# => create one and add it
			# generateNewSection(sectionName, sh_name, sh_type, 
			# sh_flags, sh_addr, sh_offset, sh_size, sh_link,
			# sh_info, sh_addralign, sh_entsize)			
			newNullSection = self.generateNewSection("", 0, SH_type.SHT_NULL, 0,
				0, 0, 0, 0, 0, 0, 0)
			self.sections.append(newNullSection)

			# increase count of sections
			self.header.e_shnum += 1

			# create new ".shstrtab" section (section header string table)
			# and add it to the end of the file
			offsetNewShstrtab = len(self.data)
			nameNewShstrtab = ".shstrtab"

			# use third entry in new section header string table
			# as index for the new created section (name for ".shstrtab" is 
			# second, name for NULL section first)
			newSectionStringTableIndex = len(nameNewShstrtab) + 1 + 1

			# generate new section object and add it
			# generateNewSection(sectionName, sh_name, sh_type, 
			# sh_flags, sh_addr, sh_offset, sh_size, sh_link,
			# sh_info, sh_addralign, sh_entsize)
			newSection = self.generateNewSection(newSectionName, 
				newSectionStringTableIndex, newSectionType, newSectionFlag, 
				newSectionAddr, newSectionOffset, newSectionSize, 
				newSectionLink, newSectionInfo, newSectionAddrAlign, 
				newSectionEntsize)
			self.sections.append(newSection)

			# increase count of sections
			self.header.e_shnum += 1

			# calculate length of ".shstrtab" section
			lengthNewShstrtab = len(nameNewShstrtab) + 1 \
				+ len(newSectionName) + 1 + 1

			# generate ".shstrtab" section object and add it
			# generateNewSection(sectionName, sh_name, sh_type, 
			# sh_flags, sh_addr, sh_offset, sh_size, sh_link,
			# sh_info, sh_addralign, sh_entsize)			
			newShstrtabsection = self.generateNewSection(nameNewShstrtab, 
				1, SH_type.SHT_STRTAB, 0, 
				0, offsetNewShstrtab, lengthNewShstrtab, 0, 0, 1, 0)
			self.sections.append(newShstrtabsection)

			# increase count of sections
			self.header.e_shnum += 1

			# add section header table to the end of the file new file
			self.header.e_shoff = offsetNewShstrtab + lengthNewShstrtab

			# new section string table index is the third section
			self.header.e_shstrndx = 2


		# sections exist
		# => just add section
		else:
			# get index in the string table of the name of the new section 
			# (use size of string table to just append new name to string 
			# table)
			newSectionStringTableIndex \
				= self.sections[self.header.e_shstrndx].elfN_shdr.sh_size

			# generate new section object
			# generateNewSection(sectionName, sh_name, sh_type, 
			# sh_flags, sh_addr, sh_offset, sh_size, sh_link,
			# sh_info, sh_addralign, sh_entsize)
			newsection = self.generateNewSection(newSectionName, 
				newSectionStringTableIndex, newSectionType, newSectionFlag, 
				newSectionAddr, newSectionOffset, newSectionSize, 
				newSectionLink, newSectionInfo, newSectionAddrAlign, 
				newSectionEntsize)

			# get position of new section
			positionNewSection = None
			for i in range(self.header.e_shnum):
				if (i+1) < self.header.e_shnum:
					if (self.sections[i].elfN_shdr.sh_offset < newSectionOffset
						and self.sections[i+1].elfN_shdr.sh_offset 
						>= newSectionOffset):
						positionNewSection = i+1

						# if new section comes before string table section 
						# => adjust string table section index
						if positionNewSection <= self.header.e_shstrndx:
							self.header.e_shstrndx += 1
						break
			# insert new section at calculated position
			if positionNewSection is None:
				self.sections.append(newsection)
			else:
				self.sections.insert(positionNewSection, newsection)

			# section header table lies oft directly behind the string table
			# check if new section name would overwrite data of 
			# section header table
			# => move section header table
			if (self.header.e_shoff 
				>= (self.sections[self.header.e_shstrndx].elfN_shdr.sh_offset 
				+ self.sections[self.header.e_shstrndx].elfN_shdr.sh_size) 
				and self.header.e_shoff 
				<= (self.sections[self.header.e_shstrndx].elfN_shdr.sh_offset 
				+ self.sections[self.header.e_shstrndx].elfN_shdr.sh_size 
				+ len(newSectionName) + 1)):
				self.header.e_shoff += len(newSectionName) + 1

			# add size of new name to string table + 1 for 
			# null-terminated C string
			self.sections[self.header.e_shstrndx].elfN_shdr.sh_size \
				+= len(newSectionName) + 1

			# increase count of sections
			self.header.e_shnum += 1


	# this function extends the section size by the given size
	# return values: None
	def extendSection(self, sectionToExtend, size):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		sectionToExtend.elfN_shdr.sh_size += size


	# this function searches for a executable segment from type 
	# PT_LOAD in which the data fits
	# return values: (class Segment) manipulated segment, 
	# (int) offset in file of appended data, 
	# (int) address in memory of appended data
	def appendDataToExecutableSegment(self, data, addNewSection=False, 
		newSectionName=None, extendExistingSection=False):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# get all executable segments from type PT_LOAD
		possibleSegments = list()
		for segment in self.segments:
			if ((segment.elfN_Phdr.p_flags & P_flags.PF_X) == 1 
				and segment.elfN_Phdr.p_type == P_type.PT_LOAD):
				possibleSegments.append(segment)

		# find space for data in all possible executable segments
		found = False
		for possibleSegment in possibleSegments:
			diff_p_vaddr = None
			# find segment that comes directly after the segment to 
			# manipulate in the virtual memory
			# and get the free memory space in between
			for i in range(len(self.segments)):
				if self.segments[i] != possibleSegment:
					if ((self.segments[i].elfN_Phdr.p_vaddr 
						- (possibleSegment.elfN_Phdr.p_vaddr 
						+ possibleSegment.elfN_Phdr.p_memsz)) > 0):
						if (diff_p_vaddr is None
							or (self.segments[i].elfN_Phdr.p_vaddr 
							- (possibleSegment.elfN_Phdr.p_vaddr 
							+ possibleSegment.elfN_Phdr.p_memsz)) 
							< diff_p_vaddr):
							diff_p_vaddr = self.segments[i].elfN_Phdr.p_vaddr \
							- (possibleSegment.elfN_Phdr.p_vaddr \
							+ possibleSegment.elfN_Phdr.p_memsz)
				else: # get position in list of possible segment
					segmentNumber = i
			# check if data to append fits in space
			if diff_p_vaddr > len(data):
				found = True
				break
		if not found:
			raise ValueError("Size of data to append: %d Not enough space" \
				+ " after existing executable segment found." % len(data))

		# append data to segment
		newDataOffset, newDataMemoryAddr = self.appendDataToSegment(data,
			segmentNumber, addNewSection=addNewSection,
			newSectionName=newSectionName,
			extendExistingSection=extendExistingSection)

		# return manipulated segment, offset of appended data in file and 
		# memory address of appended data
		return self.segments[segmentNumber], newDataOffset, newDataMemoryAddr


	# this function gets the next segment of the given one and the 
	# free space in memory in between
	# return values: (class Segment) next segment, (int) free space; 
	# both None if no following segment was found
	def getNextSegmentAndFreeSpace(self, segmentToSearch):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# find segment that comes directly after the segment to 
		# manipulate in the virtual memory
		diff_p_vaddr = None
		nextSegment = None
		for segment in self.segments:
			if segment != segmentToSearch:
				if ((segment.elfN_Phdr.p_vaddr 
					- (segmentToSearch.elfN_Phdr.p_vaddr 
					+ segmentToSearch.elfN_Phdr.p_memsz)) > 0):
					if (diff_p_vaddr is None
						or (segment.elfN_Phdr.p_vaddr 
						- (segmentToSearch.elfN_Phdr.p_vaddr 
						+ segmentToSearch.elfN_Phdr.p_memsz)) 
						< diff_p_vaddr):
						diff_p_vaddr = segment.elfN_Phdr.p_vaddr \
							- (segmentToSearch.elfN_Phdr.p_vaddr \
							+ segmentToSearch.elfN_Phdr.p_memsz)
						nextSegment = segment

		# return nextSegment and free space
		return nextSegment, diff_p_vaddr


	# this function is a wrapper function for 
	# getNextSegmentAndFreeSpace(segmentToSearch)
	# which returns only the free space in memory after the segment
	# return values: (int) free space; None if no following segment was found
	def getFreeSpaceAfterSegment(self, segmentToSearch):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		nextSegment, diff_p_vaddr \
			= self.getNextSegmentAndFreeSpace(segmentToSearch)
		return diff_p_vaddr


	# this function removes all section header entries
	# return values: None
	def removeSectionHeaderTable(self):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		self.header.e_shoff = 0
		self.header.e_shnum = 0
		self.header.e_shentsize = 0
		self.header.e_shstrndx = Shstrndx.SHN_UNDEF
		self.sections = list()


	# this function overwrites data on the given offset 
	# return values: None
	def writeDataToFileOffset(self, offset, data, force=False):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# get the segment to which the changed data belongs to
		segmentToManipulate = None
		for segment in self.segments:
			if (offset > segment.elfN_Phdr.p_offset
				and offset < (segment.elfN_Phdr.p_offset 
				+ segment.elfN_Phdr.p_filesz)):
				segmentToManipulate = segment
				break

		# check if segment was found
		if (segmentToManipulate is None
			and force is False):
			raise ValueError('Segment with offset 0x%x not found ' \
				+ '(use "force=True" to ignore this check).' % offset)

		# calculate position of data to manipulate in segment
		dataPosition = offset - segmentToManipulate.elfN_Phdr.p_offset

		# check if data to manipulate fits in segment
		if (len(data) > (segmentToManipulate.elfN_Phdr.p_filesz - dataPosition)
			and force is False):
			raise ValueError('Size of data to manipulate: %d Not enough ' \
				+ 'space in segment (Available: %d; use "force=True" to ' \
				+ 'ignore this check).' % (len(data), 
				(segmentToManipulate.elfN_Phdr.p_filesz - offset)))

		# change data
		for i in range(len(data)):
			self.data[offset + i] = data[i]


	# this function converts the virtual memory address to the file offset
	# return value: (int) offset in file (or None if not found)
	def virtualMemoryAddrToFileOffset(self, memoryAddr):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# get the segment to which the virtual memory address belongs to
		foundSegment = None
		for segment in self.segments:
			if (memoryAddr > segment.elfN_Phdr.p_vaddr
				and memoryAddr < (segment.elfN_Phdr.p_vaddr 
				+ segment.elfN_Phdr.p_memsz)):
				foundSegment = segment
				break

		# check if segment was found
		if foundSegment is None:
			return None

		# check if file is mapped 1:1 to memory
		if foundSegment.elfN_Phdr.p_filesz != foundSegment.elfN_Phdr.p_memsz:
			# check if the memory address relative to the virtual memory 
			# address of the segment lies within the file size of the segment
			if ((memoryAddr - segment.elfN_Phdr.p_vaddr) > 0
				and (memoryAddr - segment.elfN_Phdr.p_vaddr) 
				< foundSegment.elfN_Phdr.p_filesz):
					pass
			else:
				raise ValueError("Can not convert virtual memory address " \
					+ "to file offset.")

		relOffset = memoryAddr - foundSegment.elfN_Phdr.p_vaddr
		return foundSegment.elfN_Phdr.p_offset + relOffset


	# this function converts the file offset to the virtual memory address
	# return value: (int) virtual memory address (or None if not found)
	def fileOffsetToVirtualMemoryAddr(self, offset):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# get the segment to which the file offset belongs to
		foundSegment = None
		for segment in self.segments:
			if (offset > segment.elfN_Phdr.p_offset
				and offset < (segment.elfN_Phdr.p_offset 
				+ segment.elfN_Phdr.p_filesz)):
				foundSegment = segment
				break

		# check if segment was found
		if foundSegment is None:
			return None

		# check if file is mapped 1:1 to memory
		if foundSegment.elfN_Phdr.p_filesz != foundSegment.elfN_Phdr.p_memsz:
			raise ValueError("Data not mapped 1:1 from file to memory." \
				+ " Can not convert virtual memory address to file offset.")

		return foundSegment.elfN_Phdr.p_vaddr + offset


	# this function overwrites an entry in the got 
	# (global offset table) in the file
	# return values: None
	def modifyGotEntryAddr(self, name, memoryAddr):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# search for name in jump relocation entries
		entryToModify = None
		for jmpEntry in self.jumpRelocationEntries:
			if jmpEntry.name == name:
				entryToModify = jmpEntry
				break
		if entryToModify is None:
			raise ValueError('Jump relocation entry with the name "%s" ' \
				+ 'was not found.' % name)

		# calculate file offset of got 
		entryOffset = self.virtualMemoryAddrToFileOffset(
			entryToModify.r_offset)

		# generate list with new memory address for got
		# for 32 bit systems only
		newGotAddr = list()
		newGotAddr.append(chr((memoryAddr & 0xff)))
		newGotAddr.append((chr((memoryAddr >> 8) & 0xff)))
		newGotAddr.append((chr((memoryAddr >> 16) & 0xff)))
		newGotAddr.append((chr((memoryAddr >> 24) & 0xff)))

		# overwrite old offset
		self.writeDataToFileOffset(entryOffset, newGotAddr)


	# this function gets the value of the got (global offset table) entry 
	# (a memory address to jump to)
	# return values: (int) value (memory address) of got entry
	def getValueOfGotEntry(self, name):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# search for name in jump relocation entries
		entryToModify = None
		for jmpEntry in self.jumpRelocationEntries:
			if jmpEntry.name == name:
				entryToModify = jmpEntry
				break
		if entryToModify is None:
			raise ValueError('Jump relocation entry with the name "%s" ' \
				+ 'was not found.' % name)

		# calculate file offset of got 
		entryOffset = self.virtualMemoryAddrToFileOffset(
			entryToModify.r_offset)

		return ((ord(self.data[entryOffset + 3]) \
			<< 24) \
			+ (ord(self.data[entryOffset + 2]) \
			<< 16) \
			+ (ord(self.data[entryOffset + 1]) \
			<< 8) \
			+ ord(self.data[entryOffset]))


	# this function gets the memory address of the got 
	# (global offset table) entry
	# return values: (int) memory address of got entry
	def getMemAddrOfGotEntry(self, name):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# search for name in jump relocation entries
		entryToSearch = None
		for jmpEntry in self.jumpRelocationEntries:
			if jmpEntry.name == name:
				entryToSearch = jmpEntry
				break
		if entryToSearch is None:
			raise ValueError('Jump relocation entry with the name "%s"' \
				+ ' was not found.' % name)

		return entryToSearch.r_offset


	# this functions removes the first section given by name
	# return values: None
	def deleteSectionByName(self, name):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# search for the first section with the given name
		found = False
		for sectionNo in range(len(self.sections)):
			if self.sections[sectionNo].sectionName == name:
				found = True
				break

		# check if the section was found
		if not found:
			return

		# remove the found section 
		self.sections.pop(sectionNo)

		# modify ELF header 
		# => change section string table index and number of sections
		if sectionNo < self.header.e_shstrndx:
			self.header.e_shstrndx = self.header.e_shstrndx - 1
		elif sectionNo == self.header.e_shstrndx:
			self.header.e_shstrndx = 0
		self.header.e_shnum = self.header.e_shnum - 1


	# this function searches for the first jump relocation entry given by name
	# return values: (ElfN_Rel) jump relocation entry
	def getJmpRelEntryByName(self, name):

		# check if the file was completely parsed before
		if self.fileParsed is False:
			raise ValueError("Operation not possible. " \
				+ "File was not completely parsed before.")

		# search for the first jump relocation entry with the given name
		foundEntry = None
		for jmpRelEntry in self.jumpRelocationEntries:
			if jmpRelEntry.symbol.symbolName == name:
				foundEntry = jmpRelEntry
				break

		# check if jump relocation entry was found
		if foundEntry is None:
			raise ValueError('Jump relocation entry with the name "%s"' \
				+ ' was not found.' % name)

		return foundEntry