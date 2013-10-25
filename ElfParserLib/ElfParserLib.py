#!/usr/bin/python

import binascii
import sys
import hashlib


class ElfN_Ehdr:

	class EI_OSABI:
		'''
		This  byte  identifies  the operating system and ABI to which the object is targeted.  Some fields in other ELF structures have flags and values that have platform-specific  meanings;  the  interpretation  of  those fields is determined by the value of this byte.  E.g.:

		ELFOSABI_NONE       Same as ELFOSABI_SYSV (0x00)
		ELFOSABI_SYSV       UNIX System V ABI.
		ELFOSABI_HPUX       HP-UX ABI.
		ELFOSABI_NETBSD     NetBSD ABI.
		ELFOSABI_LINUX      Linux ABI. (0x03)
		ELFOSABI_SOLARIS    Solaris ABI.
		ELFOSABI_IRIX       IRIX ABI.
		ELFOSABI_FREEBSD    FreeBSD ABI.
		ELFOSABI_TRU64      TRU64 UNIX ABI.
		ELFOSABI_ARM        ARM architecture ABI.
		ELFOSABI_STANDALONE Stand-alone (embedded) ABI.
		'''
		reverse_lookup = {0x0: "ELFOSABI_NONE", 0x3: "ELFOSABI_LINUX"}
		ELFOSABI_NONE = 0x0
		ELFOSABI_LINUX = 0x3

	class EI_VERSION:
		'''
		The version number of the ELF specification:
		EV_NONE       Invalid version. (0x00)
		EV_CURRENT    Current version. (0x01)
		'''
		reverse_lookup = {0x0: "EV_NONE", 0x1: "EV_CURRENT"}
		EV_NONE = 0x0
		EV_CURRENT = 0x1

	class EI_DATA:
		'''
		The sixth byte of e_ident specifies the data encoding of the processor-specific data in the file. Currently  these encodings are supported:

		ELFDATANONE   Unknown data format. (0x00)
		ELFDATA2LSB   Two's complement, little-endian. (0x01)
		ELFDATA2MSB   Two's complement, big-endian. (0x02)
		'''
		reverse_lookup = {0x0: "ELFDATANONE", 0x1: "ELFDATA2LSB", 0x2: "ELFDATA2MSB"}
		ELFDATANONE = 0x0
		ELFDATA2LSB = 0x1
		ELFDATA2MSB = 0x2

	class EI_CLASS:
		'''
		EI_CLASS The fifth byte of e_ident identifies the architecture for this binary:

		ELFCLASSNONE  This class is invalid. (0x00)
		ELFCLASS32    This  defines  the  32-bit architecture.  It supports machines with files and virtual address spaces up to 4 Gigabytes. (0x01)
		ELFCLASS64    This defines the 64-bit architecture. (0x02)
		'''
		ELFCLASSNONE = 0x0
		ELFCLASS32 = 0x1
		ELFCLASS64 = 0x2

	class E_machine:
		'''
		uint16_t      e_machine;

		This member specifies the required architecture for an individual file.  E.g.:

		EM_NONE     An unknown machine. (0x0)
		EM_M32      AT&T WE 32100. (0x1)
		EM_SPARC    Sun Microsystems SPARC. (0x2)
		EM_386      Intel 80386. (0x3)
		EM_68K      Motorola 68000. (0x4)
		EM_88K      Motorola 88000. (0x5)
		EM_860      Intel 80860. (0x7)
		EM_MIPS     MIPS RS3000 (big-endian only). (0x8)
		EM_PARISC   HP/PA. (0xF)
		EM_SPARC32PLUS SPARC with enhanced instruction set. (0x12)
		EM_PPC      PowerPC. (0x14)
		EM_PPC64    PowerPC 64-bit. (0x15)
		EM_S390     IBM S/390 (0x16)
		EM_ARM      Advanced RISC Machines (0x28)
		EM_SH       Renesas SuperH (0x2A)
		EM_SPARCV9  SPARC v9 64-bit. (0x2B)
		EM_IA_64    Intel Itanium (0x32)
		EM_X86_64   AMD x86-64 (0x3E)
		EM_VAX      DEC Vax. (0x4B)
		'''
		reverse_lookup = {0x0: "EM_NONE", 0x1: "EM_M32", 0x2: "EM_SPARC", 0x3: "EM_386", 0x4: "EM_68K", 0x5: "EM_88K", 0x7: "EM_860", 0x8: "EM_MIPS", 0xF: "EM_PARISC", 0x12: "EM_SPARC32PLUS", 0x14: "EM_PPC", 0x15: "EM_PPC64", 0x16: "EM_S390", 0x28: "EM_ARM", 0x2A: "EM_SH", 0x2B: "EM_SPARCV9", 0x32: "EM_IA_64", 0x3E: "EM_X86_64", 0x4B: "EM_VAX"}
		EM_NONE = 0x0
		EM_M32 = 0x1
		EM_SPARC = 0x2
		EM_386 = 0x3
		EM_68K = 0x3
		EM_88K = 0x4
		EM_860 = 0x7
		EM_MIPS = 0x8
		EM_PARISC = 0xF
		EM_SPARC32PLUS = 0x12
		EM_PPC = 0x14
		EM_PPC64 = 0x15
		EM_S390 = 0x16
		EM_ARM = 0x28
		EM_SH = 0x2A
		EM_SPARCV9 = 0x2B
		EM_IA_64 = 0x32
		EM_X86_64 = 0x3E
		EM_VAX = 0x4B

	class E_type:
		'''
		uint16_t      e_type;

		This member of the structure identifies the object file type:

		ET_NONE     An unknown type. (0x0)
		ET_REL      A relocatable file. (0x1)
		ET_EXEC     An executable file. (0x2)
		ET_DYN      A shared object. (0x3)
		ET_CORE     A core file. (0x4)
		'''
		reverse_lookup = {0x0: "T_NONE", 0x1: "ET_REL", 0x2: "ET_EXEC", 0x3: "ET_DYN", 0x4: "ET_CORE"}
		ET_NONE = 0x0
		ET_REL = 0x1
		ET_EXEC = 0x2
		ET_DYN = 0x3
		ET_CORE = 0x4


	'''
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
	def __init__(self):
		self.e_ident = list()
		for i in range(16):
			self.e_ident.append("\x00")
		self.e_type = None
		self.e_machine = None
		self.e_version = None
		self.e_entry = None
		self.e_phoff = None
		self.e_shoff = None
		self.e_flags = None
		self.e_ehsize = None
		self.e_phentsize = None
		self.e_phnum = None
		self.e_shentsize = None
		self.e_shnum = None
		self.e_shstrndx = None




class Shstrndx:
	'''
	SHN_UNDEF (0)     This  value  marks  an  undefined,  missing, irrelevant, or otherwise meaningless section reference.  For
	example, a symbol "defined" relative to section number SHN_UNDEF is an undefined symbol.

	SHN_LORESERVE (0xff00) This value specifies the lower bound of the range of reserved indices.

	SHN_LOPROC (0xff00)    Values greater than or equal to SHN_HIPROC are reserved for processor-specific semantics.

	SHN_HIPROC (0xff1f)    Values less than or equal to SHN_LOPROC are reserved for processor-specific semantics.

	SHN_ABS (0xfff1)       This value specifies absolute values for the corresponding reference.  For example, symbols defined relative
	to section number SHN_ABS have absolute values and are not affected by relocation.

	SHN_COMMON (0xfff2)    Symbols  defined  relative  to  this  section are common symbols, such as Fortran COMMON or unallocated C
	external variables.

	SHN_HIRESERVE (0xffff) This value specifies the upper bound of the range of reserved indices between SHN_LORESERVE and SHN_HIRESERVE,
	inclusive; the values do not reference the section header table.  That is, the section header table does not contain entries for the reserved indices.
	'''
	SHN_UNDEF = 0x0
	SHN_LORESERVE = 0xff00
	SHN_LOPROC = 0xff00
	SHN_HIPROC = 0xff1f
	SHN_ABS = 0xfff1
	SHN_COMMON = 0xfff2
	SHN_HIRESERVE = 0xffff



class Section:
	def __init__(self):
		self.sectionName = ""
		# for 32 bit systems only
		self.elfN_shdr = Elf32_Shdr() # change here to load Elf64_Shdr
		


class Elf32_Shdr:
	'''
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
	'''
	def __init__(self):
		self.sh_name = None
		self.sh_type = None
		self.sh_flags = None
		self.sh_offset = None
		self.sh_size = None
		self.sh_link = None
		self.sh_info = None
		self.sh_addralign = None
		self.sh_entsize = None


# section headers sh_flags values
class SH_flags:
	'''
	SHF_WRITE (0x1)      This section contains data that should be writable during process execution.

	SHF_ALLOC (0x2)      This  section occupies memory during process execution.  Some control sections do not reside in the memory
	image of an object file.  This attribute is off for those sections.

	SHF_EXECINSTR (0x4)  This section contains executable machine instructions.

	SHF_MASKPROC (0xf0000000)   All bits included in this mask are reserved for processor-specific semantics.
	'''
	SHF_WRITE = 0x1
	SHF_ALLOC = 0x2
	SHF_EXECINSTR = 0x4
	SHF_MASKPROC = 0xf0000000


# section headers sh_type values
class SH_type:
	'''
	SHT_NULL (0)      This  value  marks the section header as inactive.  It does not have an associated section.  Other members
	of the section header have undefined values.

	SHT_PROGBITS (1)  This section holds information defined by the program, whose format and meaning are determined  solely  by
	the program.

	SHT_SYMTAB (2)   This section holds a symbol table.  Typically, SHT_SYMTAB provides symbols for link editing, though it may
	also be used for dynamic linking.  As a complete symbol table, it may contain many symbols unnecessary for
	dynamic linking.  An object file can also contain a SHT_DYNSYM section.

	SHT_STRTAB (3)     This section holds a string table.  An object file may have multiple string table sections.

	SHT_RELA (4)     This  section holds relocation entries with explicit addends, such as type Elf32_Rela for the 32-bit class
	of object files.  An object may have multiple relocation sections.

	SHT_HASH (5)      This section holds a symbol hash table.  An object participating in dynamic linking must contain a  symbol
	hash table.  An object file may have only one hash table.

	SHT_DYNAMIC (6)   This section holds information for dynamic linking.  An object file may have only one dynamic section.

	SHT_NOTE (7)      This section holds information that marks the file in some way.

	SHT_NOBITS (8)    A  section of this type occupies no space in the file but otherwise resembles SHT_PROGBITS.  Although this
	section contains no bytes, the sh_offset member contains the conceptual file offset.

	SHT_REL (9)       This section holds relocation offsets without explicit addends, such as  type  Elf32_Rel  for  the  32-bit
	class of object files.  An object file may have multiple relocation sections.

	SHT_SHLIB (10)     This section is reserved but has unspecified semantics.

	SHT_DYNSYM (11)    This section holds a minimal set of dynamic linking symbols.  An object file can also contain a SHT_SYMTAB
	section.

	SHT_LOPROC (0x70000000)    This value up to and including SHT_HIPROC is reserved for processor-specific semantics.

	SHT_HIPROC (0x7fffffff)    This value down to and including SHT_LOPROC is reserved for processor-specific semantics.

	SHT_LOUSER (0x80000000)    This value specifies the lower bound of the range of indices reserved for application programs.

	SHT_HIUSER (0xffffffff)    This value specifies the upper bound of the range of indices reserved for application  programs.   Section
	types  between  SHT_LOUSER and SHT_HIUSER may be used by the application, without conflicting with current
	'''
	reverse_lookup = {0x0: "SHT_NULL", 0x1: "SHT_PROGBITS", 0x2: "SHT_SYMTAB", 0x3: "SHT_STRTAB", 0x4: "SHT_RELA", 0x5: "SHT_HASH", 0x6: "SHT_DYNAMIC", 0x7: "SHT_NOTE", 0x8: "SHT_NOBITS", 0x9: "SHT_REL", 0xA: "SHT_SHLIB", 0xB: "SHT_DYNSYM", 0x70000000: "SHT_LOPROC", 0x7fffffff: "SHT_HIPROC", 0x80000000: "SHT_LOUSER", 0xffffffff: "SHT_HIUSER"}
	SHT_NULL = 0x0
	SHT_PROGBITS = 0x1
	SHT_SYMTAB = 0x2
	SHT_STRTAB = 0x3
	SHT_RELA = 0x4
	SHT_HASH = 0x5
	SHT_DYNAMIC = 0x6
	SHT_NOTE = 0x7
	SHT_NOBITS = 0x8
	SHT_REL = 0x9
	SHT_SHLIB = 0xA
	SHT_DYNSYM = 0xB
	SHT_LOPROC = 0x70000000
	SHT_HIPROC = 0x7fffffff
	SHT_LOUSER = 0x80000000
	SHT_HIUSER = 0xffffffff


class Segment:
	def __init__(self):
		# for 32 bit systems only
		self.elfN_Phdr = Elf32_Phdr() # change here to load Elf64_Phdr
		self.sectionsWithin = list()
		self.segmentsWithin = list()


class Elf32_Phdr:
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
	'''
	def __init__(self):
		self.p_type = None
		self.p_offset = None
		self.p_vaddr = None
		self.p_paddr = None
		self.p_filesz = None
		self.p_memsz = None
		self.p_flags = None
		self.p_align = None



# program headers p_type values
class P_type:
	'''
	PT_NULL (0)     The array element is unused and the other members' values are undefined.  This lets the program header have
	ignored entries.

	PT_LOAD (1)     The array element specifies a loadable segment, described by p_filesz and p_memsz.  The bytes from the file
	are mapped to the beginning of the memory segment.  If the segment's memory size p_memsz is larger than the
	file  size p_filesz, the "extra" bytes are defined to hold the value 0 and to follow the segment's initialized area.  
	The file size may not be larger than the memory size.  Loadable segment entries in the  program
	header table appear in ascending order, sorted on the p_vaddr member.

	PT_DYNAMIC (2)  The array element specifies dynamic linking information.

	PT_INTERP (3)   The  array  element  specifies  the  location and size of a null-terminated pathname to invoke as an interpreter.  
	This segment type is meaningful only  for  executable  files  (though  it  may  occur  for  shared
	objects).   However it may not occur more than once in a file.  If it is present, it must precede any loadable segment entry.

	PT_NOTE (4)     The array element specifies the location and size for auxiliary information.

	PT_SHLIB (5)    This segment type is reserved but has unspecified semantics.  Programs that contain  an  array  element  of
	this type do not conform to the ABI.

	PT_PHDR (6)     The  array element, if present, specifies the location and size of the program header table itself, both in
	the file and in the memory image of the program.  This segment type may not occur more than once in a file.
	Moreover,  it may only occur if the program header table is part of the memory image of the program.  If it
	is present, it must precede any loadable segment entry.

	PT_LOPROC (0x70000000)   Values greater than or equal to PT_HIPROC are reserved for processor-specific semantics.

	PT_HIPROC (0x7fffffff)  Values less than or equal to PT_LOPROC are reserved for processor-specific semantics.

	PT_GNU_STACK GNU extension which is used by the Linux kernel to control the state of the stack via the flags set in  the
	p_flags member.
	'''
	reverse_lookup = {0x0: "PT_NULL", 0x1: "PT_LOAD", 0x2: "PT_DYNAMIC", 0x3: "PT_INTERP", 0x4: "PT_NOTE", 0x5: "PT_SHLIB", 0x6: "PT_PHDR", 0x70000000: "PT_LOPROC", 0x7fffffff: "PT_HIPROC", 0x6474E550: "PT_GNU_EH_FRAME"}
	PT_NULL = 0x0
	PT_LOAD = 0x1
	PT_DYNAMIC = 0x2
	PT_INTERP = 0x3
	PT_NOTE = 0x4
	PT_SHLIB = 0x5
	PT_PHDR = 0x6
	PT_LOPROC = 0x70000000
	PT_HIPROC = 0x7fffffff
	PT_GNU_EH_FRAME = 0x6474E550

class P_flags:
	PF_X = 0x1
	PF_W = 0x2
	PF_R = 0x4


class D_tag:
	'''
	DT_NULL     Marks end of dynamic section

	DT_NEEDED   String table offset to name of a needed library

	DT_PLTRELSZ Size in bytes of PLT relocs

	DT_PLTGOT   Address of PLT and/or GOT

	DT_HASH     Address of symbol hash table

	DT_STRTAB   Address of string table

	DT_SYMTAB   Address of symbol table

	DT_RELA     Address of Rela relocs table

	DT_RELASZ   Size in bytes of Rela table

	DT_RELAENT  Size in bytes of a Rela table entry

	DT_STRSZ    Size in bytes of string table	

	DT_SYMENT   Size in bytes of a symbol table entry

	DT_INIT     Address of the initialization function

	DT_FINI     Address of the termination function

	DT_SONAME   String table offset to name of shared object

	DT_RPATH    String table offset to library search path (deprecated)

	DT_SYMBOLIC Alert linker to search this shared object before the executable for symbols

	DT_REL      Address of Rel relocs table

	DT_RELSZ    Size in bytes of Rel table

	DT_RELENT   Size in bytes of a Rel table entry

	DT_PLTREL   Type of reloc the PLT refers (Rela or Rel)

	DT_DEBUG    Undefined use for debugging

	DT_TEXTREL  Absence of this indicates no relocs should apply to a nonwritable segment

	DT_JMPREL   Address of reloc entries solely for the PLT

	DT_BIND_NOW Instruct dynamic linker to process all relocs before transferring control to the executable

	DT_RUNPATH  String table offset to library search path

	DT_LOPROC   Start of processor-specific semantics

	DT_HIPROC   End of processor-specific semantics
	'''
	reverse_lookup = {0: "DT_NULL", 1: "DT_NEEDED", 2: "DT_PLTRELSZ", 3: "DT_PLTGOT", 4: "DT_HASH", 5: "DT_STRTAB", 6: "DT_SYMTAB", 7: "DT_RELA", 8: "DT_RELASZ", 9: "DT_RELAENT", 10: "DT_STRSZ", 11: "DT_SYMENT", 12: "DT_INIT", 13: "DT_FINI", 14: "DT_SONAME", 15: "DT_RPATH", 16: "DT_SYMBOLIC", 17: "DT_REL", 18: "DT_RELSZ", 19: "DT_RELENT", 20: "DT_PLTREL", 21: "DT_DEBUG", 22: "DT_TEXTREL", 23: "DT_JMPREL", 0x70000000: "DT_LOPROC", 0x7fffffff: "DT_HIPROC", 0x6ffffef5: "DT_GNU_HASH", 0x6ffffffe: "DT_VERNEED", 0x6fffffff: "DT_VERNEEDNUM", 0x6ffffff0: "DT_VERSYM"}
	DT_NULL = 0
	DT_NEEDED = 1
	DT_PLTRELSZ = 2
	DT_PLTGOT = 3
	DT_HASH = 4
	DT_STRTAB = 5
	DT_SYMTAB = 6
	DT_RELA = 7
	DT_RELASZ = 8
	DT_RELAENT = 9
	DT_STRSZ = 10
	DT_SYMENT = 11
	DT_INIT = 12
	DT_FINI = 13
	DT_SONAME = 14
	DT_RPATH = 15
	DT_SYMBOLIC = 16
	DT_REL = 17
	DT_RELSZ = 18
	DT_RELENT = 19
	DT_PLTREL = 20
	DT_DEBUG = 21
	DT_TEXTREL = 22
	DT_JMPREL = 23
	#DT_BIND_NOW
	#DT_RUNPATH
	DT_LOPROC = 0x70000000
	DT_HIPROC = 0x7fffffff
	DT_GNU_HASH = 0x6ffffef5
	DT_VERNEED = 0x6ffffffe
	DT_VERNEEDNUM = 0x6fffffff
	DT_VERSYM = 0x6ffffff0


class ElfN_Dyn:
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
	def __init__(self):
		self.d_tag = None
		self.d_un = None



class ElfN_Rel:
	'''
	typedef struct elf32_rel {
		Elf32_Addr    r_offset;
		Elf32_Word    r_info;
	} Elf32_Rel;

	typedef struct elf64_rel {
		Elf64_Addr r_offset;  /* Location at which to apply the action */
		Elf64_Xword r_info;   /* index and type of relocation */
	} Elf64_Rel;

	Macros for 32 bit systems
	#define ELF32_R_SYM(i)		((i)>>8)
	#define ELF32_R_TYPE(i)		((unsigned char)(i))
	#define ELF32_R_INFO(s,t)	(((s)<<8)+(unsigned char)(t))
	'''
	def __init__(self):
		# in executable and share object files => r_offset holds a virtual address
		self.r_offset = None
		self.r_info = None

		# for 32 bit systems calculated: "(unsigned char)(r_info)" or just "r_info & 0xFF"
		self.r_type = None

		# for 32 bit systems calculated: "r_info >> 8"
		self.r_sym = None

		# for 32 bit systems:
		# r_info = (r_sym << 8) + (r_type & 0xFF)

		# for 32 bit systems
		self.symbol = ElfN_Sym()

		self.name = ""


class ElfN_Sym:
	'''
	typedef struct elf32_sym {
		Elf32_Word		st_name;
		Elf32_Addr		st_value;
		Elf32_Word		st_size;
		unsigned char	st_info;
		unsigned char	st_other;
		Elf32_Half		st_shndx;
	} Elf32_Sym;

	typedef struct elf64_sym {
		Elf64_Word 		st_name;           /* Symbol name, index in string tbl */
		unsigned char 	st_info;        /* Type and binding attributes */
		unsigned char 	st_other;       /* No defined meaning, 0 */
		Elf64_Half 		st_shndx;          /* Associated section index */
		Elf64_Addr 		st_value;          /* Value of the symbol */
		Elf64_Xword 	st_size;          /* Associated symbol size */
	} Elf64_Sym;	
	'''
	def __init__(self):
		st_name = None
		st_value = None
		st_size = None
		st_info = None
		st_other = None
		st_shndx = None



class R_type:
	'''
	R_386_GOT32 	This relocation type computes the distance from the base of the global offset
	           		table to the symbol's global offset table entry. It additionally instructs the link
	            	editor to build a global offset table.

	R_386_PLT32 	This relocation type computes the address of the symbol's procedure linkage
	             	table entry and additionally instructs the link editor to build a procedure linkage
	            	table.

	R_386_COPY 		The link editor creates this relocation type for dynamic linking. Its offset
	          		member refers to a location in a writable segment. The symbol table index
	        		specifies a symbol that should exist both in the current object file and in a shared
	            	object. During execution, the dynamic linker copies data associated with the
	           		shared object's symbol to the location specified by the offset.

	R_386_GLOB_DAT 	This relocation type is used to set a global offset table entry to the address of the
	              	specified symbol. The special relocation type allows one to determine the
	               	correspondence between symbols and global offset table entries.

	R_3862_JMP_SLOT The link editor creates this relocation type for dynamic linking. Its offset
	               	member gives the location of a procedure linkage table entry. The dynamic
	              	linker modifies the procedure linkage table entry to transfer control to the desig-
	               	nated symbol's address.

	R_386_RELATIVE 	The link editor creates this relocation type for dynamic linking. Its offset
	              	member gives a location within a shared object that contains a value represent-
	             	ing a relative address. The dynamic linker computes the corresponding virtual
	            	address by adding the virtual address at which the shared object was loaded to
	           		the relative address. Relocation entries for this type must specify 0 for the sym-
	          		bol table index.

	R_386_GOTOFF 	This relocation type computes the difference between a symbol's value and the
	              	address of the global offset table. It additionally instructs the link editor to build
	             	the global offset table.

	R_386_GOTPC 	This relocation type resembles R_386_PC32, except it uses the address of the
	           		global offset table in its calculation. The symbol referenced in this relocation
	          		normally is _GLOBAL_OFFSET_TABLE_, which additionally instructs the link
	         		editor to build the global offset table.

	'''
	reverse_lookup = {0: "R_386_NONE", 1: "R_386_32", 2: "R_386_PC32", 3: "R_386_GOT32", 4: "R_386_PLT32", 5: "R_386_COPY", 6: "R_386_GLOB_DAT", 7: "R_386_JMP_SLOT", 8: "R_386_RELATIVE", 9: "R_386_GOTOFF", 10: "R_386_GOTPC"}
	R_386_NONE = 0
	R_386_32 = 1
	R_386_PC32 = 2
	R_386_GOT32 = 3
	R_386_PLT32 = 4
	R_386_COPY = 5
	R_386_GLOB_DAT = 6
	R_386_JMP_SLOT = 7
	R_386_RELATIVE = 8
	R_386_GOTOFF = 9
	R_386_GOTPC = 10





class ElfParser:

	def __init__(self, filename, force=False):
		self.header = None
		self.segments = None
		self.sections = None
		self.dynamicSegmentEntries = None
		self.jumpRelocationEntries = None
		self.relocationEntries = None
		self.data = list()

		# read file and convert data to list
		f = open(filename, "r")
		self.data = list(f.read())
		f.close()

		# parse ELF file
		self.parseElf(self.data)

		# generate md5 hash of file that was parsed
		tempHash = hashlib.md5()
		tempHash.update("".join(self.data))
		oldFileHash = tempHash.digest()

		# generate md5 hash of file that was newly generated
		tempHash = hashlib.md5()
		tempHash.update("".join(self.generateElf()))
		newFileHash = tempHash.digest()

		# check if parsed ELF file and new generated one are the same
		if oldFileHash != newFileHash and force == False:
			raise NotImplementedError('Not able to parse and re-generate ELF file correctly (use "force=True" to ignore this check).')



	def sectionHeaderEntryToList(self, sectionHeaderEntryToWrite):
		sectionHeaderEntryList = list()

		'''
		uint32_t   sh_name;
		'''
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_name & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_name >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_name >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_name >> 24) & 0xff))

		'''
		uint32_t   sh_type;
		'''
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_type & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_type >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_type >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_type >> 24) & 0xff))

		'''
		uint32_t   sh_flags;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_flags & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_flags >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_flags >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_flags >> 24) & 0xff))

		'''
		Elf32_Addr sh_addr;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_addr & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_addr >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_addr >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_addr >> 24) & 0xff))

		'''
		Elf32_Off  sh_offset;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_offset & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_offset >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_offset >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_offset >> 24) & 0xff))

		'''
		uint32_t   sh_size;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_size & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_size >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_size >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_size >> 24) & 0xff))

		'''
		uint32_t   sh_link;
		'''
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_link & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_link >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_link >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_link >> 24) & 0xff))

		'''
		uint32_t   sh_info;
		'''
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_info & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_info >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_info >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_info >> 24) & 0xff))

		'''
		uint32_t   sh_addralign;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_addralign & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_addralign >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_addralign >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_addralign >> 24) & 0xff))

		'''
		uint32_t   sh_entsize;
		'''
		# for 32 bit systems only
		sectionHeaderEntryList.append(chr(sectionHeaderEntryToWrite.sh_entsize & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_entsize >> 8) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_entsize >> 16) & 0xff))
		sectionHeaderEntryList.append(chr((sectionHeaderEntryToWrite.sh_entsize >> 24) & 0xff))

		return sectionHeaderEntryList



	def generateNewSection(self, sectionName, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize):
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


	def parseElf(self, buffer_list):

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
		self.header.e_machine = ord(buffer_list[19])*0x10 + ord(buffer_list[18])


		'''
		uint32_t      e_version;

		This member identifies the file version:

		EV_NONE     Invalid version.
		EV_CURRENT  Current version.
		'''
		self.header.e_version = ord(buffer_list[23])*0x1000000 + ord(buffer_list[22])*0x10000 + ord(buffer_list[21])*0x100 + ord(buffer_list[20])


		'''
		ElfN_Addr     e_entry;

		This member gives the virtual address to which the system first transfers control, thus starting the process. If the file has no associated entry point, this member holds zero.
		'''
		# for 32 bit systems only
		self.header.e_entry = ord(buffer_list[27])*0x1000000 + ord(buffer_list[26])*0x10000 + ord(buffer_list[25])*0x100 + ord(buffer_list[24])



		'''
		ElfN_Off      e_phoff;

		This  member holds the program header table's file offset in bytes.  If the file has no program header table, this member holds zero.
		'''
		# for 32 bit systems only
		self.header.e_phoff = ord(buffer_list[31])*0x1000000 + ord(buffer_list[30])*0x10000 + ord(buffer_list[29])*0x100 + ord(buffer_list[28])


		'''
		ElfN_Off      e_shoff;

		This member holds the section header table's file offset in bytes (from the beginning of the file).  If the file has no section header table this member holds zero.
		'''
		# for 32 bit systems only
		self.header.e_shoff = ord(buffer_list[35])*0x1000000 + ord(buffer_list[34])*0x10000 + ord(buffer_list[33])*0x100 + ord(buffer_list[32])


		'''
		uint32_t      e_flags;

		This member holds processor-specific flags associated with the file.  Flag names take the form EF_`machine_flag'. Currently no flags have been defined.
		'''
		self.header.e_flags = ord(buffer_list[39])*0x1000000 + ord(buffer_list[38])*0x10000 + ord(buffer_list[37])*0x100 + ord(buffer_list[36])


		'''
		uint16_t      e_ehsize;

		This member holds the ELF header's size in bytes.
		'''
		self.header.e_ehsize = ord(buffer_list[41])*0x100 + ord(buffer_list[40])


		'''
		uint16_t      e_phentsize;

		This member holds the size in bytes of one entry in the file's program header table; all entries are the same size.
		'''
		self.header.e_phentsize = ord(buffer_list[43])*0x100 + ord(buffer_list[42])


		'''
		uint16_t      e_phnum;

		This member holds the number of entries in the program header table.  Thus the product of e_phentsize and e_phnum gives the table's size in bytes.
		If a file has no program header, e_phnum holds the value zero.

		If  the  number  of  entries in the program header table is larger than or equal to PN_XNUM (0xffff), this member holds
		PN_XNUM (0xffff) and the real number of entries in the program header table is held in the sh_info member of  the  initial
		entry in section header table.  Otherwise, the sh_info member of the initial entry contains the value zero.

		PN_XNUM  This  is defined as 0xffff, the largest number e_phnum can have, specifying where the actual number of program
		headers is assigned.
		'''
		self.header.e_phnum = ord(buffer_list[45])*0x100 + ord(buffer_list[44])


		'''
		uint16_t      e_shentsize;

		This member holds a sections header's size in bytes.  A section header is one entry in the section  header  table;  all
		entries are the same size.
		'''
		self.header.e_shentsize = ord(buffer_list[47])*0x100 + ord(buffer_list[46])


		'''
		uint16_t      e_shnum;

		This member holds the number of entries in the section header table.  Thus the product of e_shentsize and e_shnum gives
		the section header table's size in bytes.  If a file has no section header table, e_shnum holds the value of zero.

		If the number of entries in the section header table is larger than or equal to SHN_LORESERVE (0xff00),  e_shnum  holds
		the  value zero and the real number of entries in the section header table is held in the sh_size member of the initial
		entry in section header table.  Otherwise, the sh_size member of the initial entry in the section  header  table  holds
		the value zero.
		'''
		self.header.e_shnum = ord(buffer_list[49])*0x100 + ord(buffer_list[48])


		'''
		uint16_t      e_shstrndx;

		This  member  holds  the section header table index of the entry associated with the section name string table.  If the
		file has no section name string table, this member holds the value SHN_UNDEF.

		If the index of section name string table section is larger than or equal to SHN_LORESERVE (0xff00), this member  holds
		SHN_XINDEX  (0xffff)  and  the real index of the section name string table section is held in the sh_link member of the
		initial entry in section header table.  Otherwise, the sh_link member of the initial entry in section header table contains the value zero.
		'''
		self.header.e_shstrndx = ord(buffer_list[51])*0x100 + ord(buffer_list[50])



		###############################################
		# check if ELF is supported

		'''
		EI_MAG0     The first byte of the magic number. It must be filled with ELFMAG0. (0x7f)
		EI_MAG1     The second byte of the magic number. It must be filled with ELFMAG1. ('E')
		EI_MAG2     The third byte of the magic number. It must be filled with ELFMAG2. ('L')
		EI_MAG3     The fourth byte of the magic number. It must be filled with ELFMAG3. ('F')
		'''
		if not (self.header.e_ident[0] == chr(0x7f) and self.header.e_ident[1] == 'E' and self.header.e_ident[2] == 'L' and self.header.e_ident[3] == 'F'):
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
		The sixth byte specifies the data encoding of the processor-specific data in the file.
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
		This  byte  identifies  the operating system and ABI to which the object is targeted.  Some fields in other ELF structures have flags and values that have platform-specific  meanings;  the  interpretation  of  those fields is determined by the value of this byte.
		'''
		if not (ord(self.header.e_ident[7]) == ElfN_Ehdr.EI_OSABI.ELFOSABI_NONE or ord(self.header.e_ident[7]) == ElfN_Ehdr.EI_OSABI.ELFOSABI_LINUX):
			raise NotImplementedError("EI_OSABI not yet supported")


		'''
		This byte identifies the version of the ABI to which the object is targeted.  This field is used to distinguish among incompatible versions of an ABI.  The interpretation of this version number is dependent on the ABI identified by the EI_OSABI field. Applications conforming to this specification use the value 0.
		'''
		if ord(self.header.e_ident[8]) != 0:
			raise NotImplementedError("EI_ABIVERSION not yet supported")



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

			This member specifies the name of the section.  Its value is an index into the section header string table section,  giving the location of a null-terminated string.
			'''
			tempSectionEntry.sh_name = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 3])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 2])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 1])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 0])

			'''
			uint32_t   sh_type;

			This member categorizes the section's contents and semantics.
			'''
			tempSectionEntry.sh_type = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 7])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 6])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 5])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 4])

			'''
			uint32_t   sh_flags;

			Sections support one-bit flags that describe miscellaneous attributes.  If a flag bit is set in sh_flags,  the  attribute
			is "on" for the section.  Otherwise, the attribute is "off" or does not apply.  Undefined attributes are set to zero.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_flags = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 11])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 10])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 9])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 8])

			'''
			Elf32_Addr sh_addr;

			If this section appears in the memory image of a process, this member holds the address at which the section's first byte
			should reside.  Otherwise, the member contains zero.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_addr = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 15])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 14])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 13])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 12])

			'''
			Elf32_Off  sh_offset;

			This  member's  value holds the byte offset from the beginning of the file to the first byte in the section.  One section
			type, SHT_NOBITS, occupies no space in the file, and its sh_offset member locates the conceptual placement in the file.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_offset = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 19])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 18])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 17])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 16])

			'''
			uint32_t   sh_size;

			This member holds the section's size in bytes.  Unless the section type is SHT_NOBITS, the section occupies sh_size bytes
			in the file.  A section of type SHT_NOBITS may have a nonzero size, but it occupies no space in the file.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_size = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 23])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 22])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 21])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 20])

			'''
			uint32_t   sh_link;

			This member holds a section header table index link, whose interpretation depends on the section type.
			'''
			tempSectionEntry.sh_link = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 27])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 26])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 25])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 24])

			'''
			uint32_t   sh_info;

			This member holds extra information, whose interpretation depends on the section type.
			'''
			tempSectionEntry.sh_info = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 31])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 30])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 29])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 28])

			'''
			uint32_t   sh_addralign;

			Some  sections  have  address  alignment constraints.  If a section holds a doubleword, the system must ensure doubleword
			alignment for the entire section.  That is, the value of  sh_addr  must  be  congruent  to  zero,  modulo  the  value  of
			sh_addralign.   Only zero and positive integral powers of two are allowed.  Values of zero or one mean the section has no
			alignment constraints.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_addralign = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 35])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 34])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 33])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 32])

			'''
			uint32_t   sh_entsize;

			Some sections hold a table of fixed-sized entries, such as a symbol table.  For such a section,  this  member  gives  the
			size in bytes for each entry.  This member contains zero if the section does not hold a table of fixed-size entries.
			'''
			# for 32 bit systems only
			tempSectionEntry.sh_entsize = ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 39])*0x1000000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 38])*0x10000 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 37])*0x100 + ord(buffer_list[self.header.e_shoff + i*self.header.e_shentsize + 36])

			# create new section and add to sections list
			section = Section()
			section.elfN_shdr = tempSectionEntry
			self.sections.append(section)



		###############################################
		# parse section string table

		# section string table first byte always 0 byte
		# section string table last byte always 0 byte
		# section string table holds null terminated strings
		# empty section string table => sh_size of string table section = 0 => Non-zero indexes to string table are invalid

		# check if sections exists => read whole string table
		if self.sections != list():
			stringtable_str = ""
			for i in range(self.sections[self.header.e_shstrndx].elfN_shdr.sh_size):
				stringtable_str += buffer_list[self.sections[self.header.e_shstrndx].elfN_shdr.sh_offset + i]

			# get name from string table for each section
			for i in range(len(self.sections)):

				tempName = ""
				counter = self.sections[i].elfN_shdr.sh_name
				while ord(stringtable_str[counter]) != 0 and counter < len(stringtable_str):
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

			This  member  of  the Phdr struct tells what kind of segment this array element describes or how to interpret the array
			element's information.
			'''
			tempSegment.elfN_Phdr.p_type = ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 3])*0x1000000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 2])*0x10000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 1])*0x100 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 0])

			'''
			Elf32_Off  p_offset;

			This member holds the offset from the beginning of the file at which the first byte of the segment resides.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_offset = ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 7])*0x1000000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 6])*0x10000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 5])*0x100 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 4])

			'''
			Elf32_Addr p_vaddr;

			This member holds the virtual address at which the first byte of the segment resides in memory.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_vaddr = ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 11])*0x1000000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 10])*0x10000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 9])*0x100 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 8])

			'''
			Elf32_Addr p_paddr;

			On  systems  for  which  physical  addressing  is relevant, this member is reserved for the segment's physical address.
			Under BSD this member is not used and must be zero.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_paddr = ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 15])*0x1000000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 14])*0x10000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 13])*0x100 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 12])

			'''
			uint32_t   p_filesz;

			This member holds the number of bytes in the file image of the segment.  It may be zero.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_filesz = ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 19])*0x1000000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 18])*0x10000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 17])*0x100 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 16])

			'''
			uint32_t   p_memsz;

			This member holds the number of bytes in the memory image of the segment.  It may be zero.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_memsz = ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 23])*0x1000000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 22])*0x10000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 21])*0x100 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 20])

			'''
			uint32_t   p_flags;

			This member holds a bitmask of flags relevant to the segment:

			PF_X   An executable segment.
			PF_W   A writable segment.
			PF_R   A readable segment.

			A text segment commonly has the flags PF_X and PF_R.  A data segment commonly has PF_X, PF_W and PF_R.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_flags = ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 27])*0x1000000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 26])*0x10000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 25])*0x100 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 24])
	
			'''
			uint32_t   p_align;

			This member holds the value to which the segments are aligned in memory and in the  file.   Loadable  process  segments
			must have congruent values for p_vaddr and p_offset, modulo the page size.  Values of zero and one mean no alignment is
			required.  Otherwise, p_align should be a positive, integral power of two, and p_vaddr should  equal  p_offset,  modulo
			p_align.
			'''
			# for 32 bit systems only
			tempSegment.elfN_Phdr.p_align = ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 31])*0x1000000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 30])*0x10000 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 29])*0x100 + ord(buffer_list[self.header.e_phoff + i*self.header.e_phentsize + 28])

			# check which sections are in the current segment (in memory) and add them
			for section in self.sections:
				if section.elfN_shdr.sh_addr >= tempSegment.elfN_Phdr.p_vaddr and (section.elfN_shdr.sh_addr + section.elfN_shdr.sh_size) <= (tempSegment.elfN_Phdr.p_vaddr + tempSegment.elfN_Phdr.p_memsz):
					tempSegment.sectionsWithin.append(section)

			self.segments.append(tempSegment)


		# get all segments within a segment
		for outerSegment in self.segments:
			for segmentWithin in self.segments:

				# skip if segments are the same
				if segmentWithin == outerSegment:
					continue

				# check if segmentWithin lies within the outerSegment
				if (segmentWithin.elfN_Phdr.p_offset > outerSegment.elfN_Phdr.p_offset
					and (segmentWithin.elfN_Phdr.p_offset + segmentWithin.elfN_Phdr.p_filesz) < (outerSegment.elfN_Phdr.p_offset + outerSegment.elfN_Phdr.p_filesz)):
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
		if dynamicSegment == None:
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
			dynSegmentEntry.d_tag = (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 3 + i*8])<<24) + (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 2 + i*8])<<16) + (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 1 + i*8])<<8)+ ord(self.data[dynamicSegment.elfN_Phdr.p_offset + i*8])

			'''
			union {
				Elf32_Sword d_val;
				Elf32_Addr  d_ptr;
			} d_un
			'''
			# for 32 bit systems only
			dynSegmentEntry.d_un = (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 7 + i*8])<<24) + (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 6 + i*8])<<16)+ (ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 5 + i*8])<<8) + ord(self.data[dynamicSegment.elfN_Phdr.p_offset + 4 + i*8])

			# add dynamic segment entry to list
			self.dynamicSegmentEntries.append(dynSegmentEntry)

			# check if the end of the dynamic segment array is reached
			if dynSegmentEntry.d_tag == P_type.PT_NULL:
				endReached = True
				break

		# check if end was reached with PT_NULL entry
		if not endReached:
			raise ValueError("PT_NULL was not found in segment of type PT_DYNAMIC (malformed ELF executable/shared object).")



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
				jmpRelOffset = self.virtualMemoryAddrToFileOffset(dynEntry.d_un)
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
				symbolTableOffset = self.virtualMemoryAddrToFileOffset(dynEntry.d_un)
				continue
			if dynEntry.d_tag == D_tag.DT_STRTAB:
				# get the offset in the file of the string table
				stringTableOffset = self.virtualMemoryAddrToFileOffset(dynEntry.d_un)
				continue
			if dynEntry.d_tag == D_tag.DT_STRSZ:
				stringTableSize = dynEntry.d_un


		# check if ELF got needed entries
		if (stringTableOffset == None
			or stringTableSize == None
			or symbolTableOffset == None
			or symbolEntrySize == None):
			raise ValueError("No dynamic section entry of type DT_STRTAB, DT_STRSZ, DT_SYMTAB and/or DT_SYMENT found (malformed ELF executable/shared object).")


		# check if DT_JMPREL entry exists (it is optional for ELF executables/shared objects)
		# => parse jump relocation entries
		if jmpRelOffset != None:

			# create a list for all jump relocation entries
			self.jumpRelocationEntries = list()

			# parse all jump relocation entries
			for i in range(pltRelSize / relEntrySize):
				jmpRelEntry = ElfN_Rel()
				'''
				Elf32_Addr    r_offset;
				'''
				# in executable and share object files => r_offset holds a virtual address
				# for 32 bit systems only
				jmpRelEntry.r_offset = (ord(self.data[jmpRelOffset + (i*relEntrySize) + 3])<<24) + (ord(self.data[jmpRelOffset + (i*relEntrySize) + 2])<<16) + (ord(self.data[jmpRelOffset + (i*relEntrySize) + 1])<<8)+ ord(self.data[jmpRelOffset + (i*relEntrySize)])

				'''
				Elf32_Word    r_info;
				'''
				# for 32 bit systems only
				jmpRelEntry.r_info = (ord(self.data[jmpRelOffset + (i*relEntrySize) + 7])<<24) + (ord(self.data[jmpRelOffset + (i*relEntrySize) + 6])<<16) + (ord(self.data[jmpRelOffset + (i*relEntrySize) + 5])<<8)+ ord(self.data[jmpRelOffset + (i*relEntrySize) + 4])

				# for 32 bit systems only
				# calculated: "(unsigned char)r_info" or just "r_info & 0xFF"
				jmpRelEntry.r_type = (jmpRelEntry.r_info & 0xFF)

				# for 32 bit systems only
				# calculated: "r_info >> 8"
				jmpRelEntry.r_sym = (jmpRelEntry.r_info >> 8)

				# get values from the symbol table
				'''
				Elf32_Word		st_name;
				'''
				# for 32 bit systems only
				jmpRelEntry.symbol.st_name = (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 3])<<24) + (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 2])<<16) + (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 1])<<8)+ ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize)])

				'''
				Elf32_Addr		st_value;
				'''
				# for 32 bit systems only
				jmpRelEntry.symbol.st_value = (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 7])<<24) + (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 6])<<16) + (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 5])<<8)+ ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 4])

				'''
				Elf32_Word		st_size;
				'''
				# for 32 bit systems only
				jmpRelEntry.symbol.st_size = (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 11])<<24) + (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 10])<<16) + (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 9])<<8)+ ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 8])

				'''
				unsigned char	st_info;
				'''
				# for 32 bit systems only
				jmpRelEntry.symbol.st_info = ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 12])

				'''
				unsigned char	st_other;
				'''
				# for 32 bit systems only
				jmpRelEntry.symbol.st_other = ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 13])					

				'''
				Elf32_Half		st_shndx;
				'''
				# for 32 bit systems only
				jmpRelEntry.symbol.st_shndx = (ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 15])<<8)+ ord(self.data[symbolTableOffset + (jmpRelEntry.r_sym*symbolEntrySize) + 14])

				# extract name from the string table
				temp = ""
				for i in range((stringTableOffset + stringTableSize - jmpRelEntry.symbol.st_name)):
					if self.data[stringTableOffset + jmpRelEntry.symbol.st_name + i] == "\x00":
						break
					temp += self.data[stringTableOffset + jmpRelEntry.symbol.st_name + i]
				jmpRelEntry.name = temp

				# add entry to jump relocation entries list
				self.jumpRelocationEntries.append(jmpRelEntry)


		# check if DT_REL entry exists (DT_REL is only mandatory when DT_RELA is not present)
		# => parse relocation entries
		if relOffset != None:
			# create a list for all relocation entries
			self.relocationEntries = list()

			# parse all relocation entries
			for i in range(relSize / relEntrySize):
				relEntry = ElfN_Rel()
				'''
				Elf32_Addr    r_offset;
				'''
				# in executable and share object files => r_offset holds a virtual address
				# for 32 bit systems only
				relEntry.r_offset = (ord(self.data[relOffset + (i*relEntrySize) + 3])<<24) + (ord(self.data[relOffset + (i*relEntrySize) + 2])<<16) + (ord(self.data[relOffset + (i*relEntrySize) + 1])<<8)+ ord(self.data[relOffset + (i*relEntrySize)])

				'''
				Elf32_Word    r_info;
				'''
				# for 32 bit systems only
				relEntry.r_info = (ord(self.data[relOffset + (i*relEntrySize) + 7])<<24) + (ord(self.data[relOffset + (i*relEntrySize) + 6])<<16) + (ord(self.data[relOffset + (i*relEntrySize) + 5])<<8)+ ord(self.data[relOffset + (i*relEntrySize) + 4])

				# for 32 bit systems only
				# calculated: "(unsigned char)r_info" or just "r_info & 0xFF"
				relEntry.r_type = (relEntry.r_info & 0xFF)

				# for 32 bit systems only
				# calculated: "r_info >> 8"
				relEntry.r_sym = (relEntry.r_info >> 8)	

				# get values from the symbol table
				'''
				Elf32_Word		st_name;
				'''
				# for 32 bit systems only
				relEntry.symbol.st_name = (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 3])<<24) + (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 2])<<16) + (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 1])<<8)+ ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize)])

				'''
				Elf32_Addr		st_value;
				'''
				# for 32 bit systems only
				relEntry.symbol.st_value = (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 7])<<24) + (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 6])<<16) + (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 5])<<8)+ ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 4])

				'''
				Elf32_Word		st_size;
				'''
				# for 32 bit systems only
				relEntry.symbol.st_size = (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 11])<<24) + (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 10])<<16) + (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 9])<<8)+ ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 8])

				'''
				unsigned char	st_info;
				'''
				# for 32 bit systems only
				relEntry.symbol.st_info = ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 12])

				'''
				unsigned char	st_other;
				'''
				# for 32 bit systems only
				relEntry.symbol.st_other = ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 13])					

				'''
				Elf32_Half		st_shndx;
				'''
				# for 32 bit systems only
				relEntry.symbol.st_shndx = (ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 15])<<8)+ ord(self.data[symbolTableOffset + (relEntry.r_sym*symbolEntrySize) + 14])

				# extract name from the string table
				temp = ""
				for i in range((stringTableOffset + stringTableSize - relEntry.symbol.st_name)):
					if self.data[stringTableOffset + relEntry.symbol.st_name + i] == "\x00":
						break
					temp += self.data[stringTableOffset + relEntry.symbol.st_name + i]
				relEntry.name = temp

				# add entry to relocation entries list
				self.relocationEntries.append(relEntry)			




	def printElf(self):

		# output header
		print "ELF header:"
		print "Type: %s" % ElfN_Ehdr.E_type.reverse_lookup[self.header.e_type]
		print "Version: %s" % ElfN_Ehdr.EI_VERSION.reverse_lookup[ord(self.header.e_ident[6])]
		print "Machine: %s" % ElfN_Ehdr.E_machine.reverse_lookup[self.header.e_machine]
		print "Entry point address: 0x%x" % self.header.e_entry
		print "Program header table offset in bytes: 0x%x (%d)" % (self.header.e_phoff, self.header.e_phoff)
		print "Section header table offset in bytes: 0x%x (%d)" % (self.header.e_shoff, self.header.e_shoff)
		print "Flags: 0x%x (%d)" % (self.header.e_flags, self.header.e_flags)
		print "Size of ELF header in bytes: 0x%x (%d)" % (self.header.e_ehsize, self.header.e_ehsize)
		print "Size of each program header entry in bytes: 0x%x (%d)" % (self.header.e_phentsize, self.header.e_phentsize)
		print "Number of program header entries: %d" % self.header.e_phnum
		print "Size of each sections header entry in bytes: 0x%x (%d)" % (self.header.e_shentsize, self.header.e_shentsize)
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
				print "Type: %s" % SH_type.reverse_lookup[section.elfN_shdr.sh_type]
			else:
				print "Unknown Type: 0x%x (%d)" % (section.elfN_shdr.sh_type,section.elfN_shdr.sh_type)

			print "Addr: 0x%x" % section.elfN_shdr.sh_addr
			print "Off: 0x%x" % section.elfN_shdr.sh_offset
			print "Size: 0x%x (%d)" % (section.elfN_shdr.sh_size, section.elfN_shdr.sh_size)
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
				print "Type: %s" % P_type.reverse_lookup[segment.elfN_Phdr.p_type]
			else:
				print "Unknown Type: 0x%x (%d)" % (segment.elfN_Phdr.p_type, segment.elfN_Phdr.p_type)

			print "Offset: 0x%x" % segment.elfN_Phdr.p_offset
			print "Virtual Addr: 0x%x" % segment.elfN_Phdr.p_vaddr
			print "Physical Addr: 0x%x" % segment.elfN_Phdr.p_paddr
			print "File Size: 0x%x (%d)" % (segment.elfN_Phdr.p_filesz,segment.elfN_Phdr.p_filesz)
			print "Mem Size: 0x%x (%d)" % (segment.elfN_Phdr.p_memsz,segment.elfN_Phdr.p_memsz)

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

			# get interpreter if segment is for interpreter null-terminated string
			if segment.elfN_Phdr.p_type == P_type.PT_INTERP:
				temp = ""
				for i in range(segment.elfN_Phdr.p_filesz):
					temp += self.data[segment.elfN_Phdr.p_offset + i]
				print "Interpreter: %s" % temp

			print 
			counter += 1


		# search string table entry, string table size, symbol table entry and symbol table entry size
		stringTableOffset = None
		stringTableSize = None
		symbolTableOffset = None
		symbolEntrySize = None
		for searchEntry in self.dynamicSegmentEntries:
			if searchEntry.d_tag == D_tag.DT_STRTAB:
				# data contains virtual memory address => calculate offset in file
				stringTableOffset = self.virtualMemoryAddrToFileOffset(searchEntry.d_un)
			if searchEntry.d_tag == D_tag.DT_STRSZ:
				stringTableSize = searchEntry.d_un
			if searchEntry.d_tag == D_tag.DT_SYMTAB:
				# data contains virtual memory address => calculate offset in file
				symbolTableOffset = self.virtualMemoryAddrToFileOffset(searchEntry.d_un)
			if searchEntry.d_tag == D_tag.DT_SYMENT:
				symbolEntrySize = searchEntry.d_un

		if (stringTableOffset == None
			or stringTableSize == None
			or symbolTableOffset == None
			or symbolEntrySize == None):
			raise ValueError("No dynamic section entry of type DT_STRTAB, DT_STRSZ, DT_SYMTAB and/or DT_SYMENT found (malformed ELF executable/shared object).")


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
				for i in range((stringTableOffset + stringTableSize - entry.d_un)):
					if self.data[stringTableOffset + entry.d_un + i] == "\x00":
						break
					temp += self.data[stringTableOffset + entry.d_un + i]
				print "Name/Value: 0x%x (%d) (%s)" % (entry.d_un, entry.d_un, temp)
			else:
				print "Name/Value: 0x%x (%d)" % (entry.d_un, entry.d_un)

			print
			counter += 1


		# output all jump relocation entries
		print("Jump relocation entries (%d entries)" % len(self.jumpRelocationEntries))
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
			print("%d" % counter),
			print("\t"),
			print("0x" + ("%x" % entry.r_offset).zfill(8)),
			print("\t"),

			# try to convert the virtual memory address to a file offset
			# in executable and share object files => r_offset holds a virtual address			
			try:
				print("0x" + ("%x" % self.virtualMemoryAddrToFileOffset(entry.r_offset)).zfill(8)),
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
			print("0x" + ("%x" % entry.symbol.st_value).zfill(8)),

			print("\t"),
			print(entry.name),

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
			print("%d" % counter),
			print("\t"),
			print("0x" + ("%x" % entry.r_offset).zfill(8)),
			print("\t"),

			# try to convert the virtual memory address to a file offset
			# in executable and share object files => r_offset holds a virtual address			
			try:
				print("0x" + ("%x" % self.virtualMemoryAddrToFileOffset(entry.r_offset)).zfill(8)),
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
			print("0x" + ("%x" % entry.symbol.st_value).zfill(8)),

			print("\t"),
			print(entry.name),

			print
			counter += 1

	


	# this function generates a new ELF file from the attributes of the object
	# return values: (list) generated ELF file data
	def generateElf(self):

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
				# as long as writePosition is not larger or equal to the length of the newfile list
				# => overwrite old data
				# if it is => append data
				if writePosition < len(newfile):
					newfile[writePosition] = temp[i]
				else:
					newfile.append(temp[i])	

				writePosition +=1

		# ------

		# when defined => write string table back
		if self.header.e_shstrndx != Shstrndx.SHN_UNDEF:
			for section in self.sections:
				# calculate the position on which the name should be written
				writePosition = self.sections[self.header.e_shstrndx].elfN_shdr.sh_offset + section.elfN_shdr.sh_name

				# fill list with null until writePosition is reached
				while writePosition > len(newfile):
					newfile.append("\x00")

				# write name of all sections into string table
				for i in range(len(section.sectionName)):
					# as long as writePosition is not larger or equal to the length of the newfile list
					# => overwrite old data
					# if it is => append data
					if writePosition < len(newfile):
						newfile[writePosition] = section.sectionName[i]
					else:
						newfile.append(section.sectionName[i])			
					writePosition +=1

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

			# add placeholder bytes to new file when the bytes do not already exist in the new file until size of header entry fits
			while (self.header.e_phoff + (i*self.header.e_phentsize) + self.header.e_phentsize) > len(newfile):
				newfile.append("\x00")

			'''
			uint32_t   p_type;
			'''
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 0] = (chr(self.segments[i].elfN_Phdr.p_type & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 1] = (chr((self.segments[i].elfN_Phdr.p_type >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 2] = (chr((self.segments[i].elfN_Phdr.p_type >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 3] = (chr((self.segments[i].elfN_Phdr.p_type >> 24) & 0xff))

			'''
			Elf32_Off  p_offset;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 4] = (chr(self.segments[i].elfN_Phdr.p_offset & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 5] = (chr((self.segments[i].elfN_Phdr.p_offset >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 6] = (chr((self.segments[i].elfN_Phdr.p_offset >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 7] = (chr((self.segments[i].elfN_Phdr.p_offset >> 24) & 0xff))

			'''
			Elf32_Addr p_vaddr;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 8] = (chr(self.segments[i].elfN_Phdr.p_vaddr & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 9] = (chr((self.segments[i].elfN_Phdr.p_vaddr >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 10] = (chr((self.segments[i].elfN_Phdr.p_vaddr >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 11] = (chr((self.segments[i].elfN_Phdr.p_vaddr >> 24) & 0xff))

			'''
			Elf32_Addr p_paddr;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 12] = (chr(self.segments[i].elfN_Phdr.p_paddr & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 13] = (chr((self.segments[i].elfN_Phdr.p_paddr >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 14] = (chr((self.segments[i].elfN_Phdr.p_paddr >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 15] = (chr((self.segments[i].elfN_Phdr.p_paddr >> 24) & 0xff))

			'''
			uint32_t   p_filesz;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 16] = (chr(self.segments[i].elfN_Phdr.p_filesz & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 17] = (chr((self.segments[i].elfN_Phdr.p_filesz >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 18] = (chr((self.segments[i].elfN_Phdr.p_filesz >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 19] = (chr((self.segments[i].elfN_Phdr.p_filesz >> 24) & 0xff))

			'''
			uint32_t   p_memsz;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 20] = (chr(self.segments[i].elfN_Phdr.p_memsz & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 21] = (chr((self.segments[i].elfN_Phdr.p_memsz >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 22] = (chr((self.segments[i].elfN_Phdr.p_memsz >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 23] = (chr((self.segments[i].elfN_Phdr.p_memsz >> 24) & 0xff))

			'''
			uint32_t   p_flags;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 24] = (chr(self.segments[i].elfN_Phdr.p_flags & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 25] = (chr((self.segments[i].elfN_Phdr.p_flags >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 26] = (chr((self.segments[i].elfN_Phdr.p_flags >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 27] = (chr((self.segments[i].elfN_Phdr.p_flags >> 24) & 0xff))
	
			'''
			uint32_t   p_align;
			'''
			# for 32 bit systems only
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 28] = (chr(self.segments[i].elfN_Phdr.p_align & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 29] = (chr((self.segments[i].elfN_Phdr.p_align >> 8) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 30] = (chr((self.segments[i].elfN_Phdr.p_align >> 16) & 0xff))
			newfile[self.header.e_phoff + (i*self.header.e_phentsize) + 31] = (chr((self.segments[i].elfN_Phdr.p_align >> 24) & 0xff))

		# ------

		# find dynamic segment
		dynamicSegment = None
		for segment in self.segments:
			if segment.elfN_Phdr.p_type == P_type.PT_DYNAMIC:
				dynamicSegment = segment
				break
		if dynamicSegment == None:
			raise ValueError("Segment of type PT_DYNAMIC was not found.")

		# write all dynamic segment entries back
		for i in range(len(self.dynamicSegmentEntries)):

			'''
			Elf32_Sword    d_tag;
			'''
			# for 32 bit systems only
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 0] = (chr(self.dynamicSegmentEntries[i].d_tag & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 1] = (chr((self.dynamicSegmentEntries[i].d_tag >> 8) & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 2] = (chr((self.dynamicSegmentEntries[i].d_tag >> 16) & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 3] = (chr((self.dynamicSegmentEntries[i].d_tag >> 24) & 0xff))

			'''
			union {
				Elf32_Word d_val;
				Elf32_Addr d_ptr;
			} d_un;
			'''
			# for 32 bit systems only
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 4] = (chr(self.dynamicSegmentEntries[i].d_un & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 5] = (chr((self.dynamicSegmentEntries[i].d_un >> 8) & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 6] = (chr((self.dynamicSegmentEntries[i].d_un >> 16) & 0xff))
			newfile[dynamicSegment.elfN_Phdr.p_offset + (i*8) + 7] = (chr((self.dynamicSegmentEntries[i].d_un >> 24) & 0xff))

		# overwrite rest of segment with 0x00 (default padding data)
		# (NOTE: works in all test cases, but can cause md5 parsing check to fail!)
		# for 32 bit systems only
		for i in range(dynamicSegment.elfN_Phdr.p_filesz - (len(self.dynamicSegmentEntries)*8)):
			newfile[dynamicSegment.elfN_Phdr.p_offset + (len(self.dynamicSegmentEntries)*8) + i] = "\x00"

		# ------

		# search for relocation entries in dynamic segment entries
		jmpRelOffset = None
		pltRelSize = None
		relEntrySize = None
		relOffset = None		
		relSize = None
		for dynEntry in self.dynamicSegmentEntries:
			if dynEntry.d_tag == D_tag.DT_JMPREL:
				# get the offset in the file of the jump relocation table
				jmpRelOffset = self.virtualMemoryAddrToFileOffset(dynEntry.d_un)
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
			if dynEntry.d_tag == D_tag.DT_RELSZ:
				relSize = dynEntry.d_un


		# check if DT_JMPREL entry exists (it is optional for ELF executables/shared objects)
		# => write jump relocation entries back
		if jmpRelOffset != None:
			for i in range(len(self.jumpRelocationEntries)):
				'''
				Elf32_Addr    r_offset;
				'''
				# for 32 bit systems only
				newfile[jmpRelOffset + (i*relEntrySize) + 0] = (chr(self.jumpRelocationEntries[i].r_offset & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 1] = (chr((self.jumpRelocationEntries[i].r_offset >> 8) & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 2] = (chr((self.jumpRelocationEntries[i].r_offset >> 16) & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 3] = (chr((self.jumpRelocationEntries[i].r_offset >> 24) & 0xff))

				'''
				Elf32_Word    r_info;
				'''
				# for 32 bit systems only
				newfile[jmpRelOffset + (i*relEntrySize) + 4] = (chr(self.jumpRelocationEntries[i].r_info & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 5] = (chr((self.jumpRelocationEntries[i].r_info >> 8) & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 6] = (chr((self.jumpRelocationEntries[i].r_info >> 16) & 0xff))
				newfile[jmpRelOffset + (i*relEntrySize) + 7] = (chr((self.jumpRelocationEntries[i].r_info >> 24) & 0xff))


		# check if DT_REL entry exists (DT_REL is only mandatory when DT_RELA is not present)
		# => write relocation entries back
		if relOffset != None:
			for i in range(len(self.relocationEntries)):
				'''
				Elf32_Addr    r_offset;
				'''
				# for 32 bit systems only
				newfile[relOffset + (i*relEntrySize) + 0] = (chr(self.relocationEntries[i].r_offset & 0xff))
				newfile[relOffset + (i*relEntrySize) + 1] = (chr((self.relocationEntries[i].r_offset >> 8) & 0xff))
				newfile[relOffset + (i*relEntrySize) + 2] = (chr((self.relocationEntries[i].r_offset >> 16) & 0xff))
				newfile[relOffset + (i*relEntrySize) + 3] = (chr((self.relocationEntries[i].r_offset >> 24) & 0xff))

				'''
				Elf32_Word    r_info;
				'''
				# for 32 bit systems only
				newfile[relOffset + (i*relEntrySize) + 4] = (chr(self.relocationEntries[i].r_info & 0xff))
				newfile[relOffset + (i*relEntrySize) + 5] = (chr((self.relocationEntries[i].r_info >> 8) & 0xff))
				newfile[relOffset + (i*relEntrySize) + 6] = (chr((self.relocationEntries[i].r_info >> 16) & 0xff))
				newfile[relOffset + (i*relEntrySize) + 7] = (chr((self.relocationEntries[i].r_info >> 24) & 0xff))	

		# ------

		return newfile




	# this function writes the generated ELF file back
	# return values: None
	def writeElf(self, filename):
		f = open(filename, "w")
		f.write("".join(self.generateElf()))
		f.close()




	# this function appends data to a selected segment number (if it fits)
	# return values: (int) offset in file of appended data, (int) address in memory of appended data
	def appendDataToSegment(self, data, segmentNumber, addNewSection=False, newSectionName=None, extendExistingSection=False):

		segmentToExtend = self.segments[segmentNumber]

		# find segment that comes directly after the segment to manipulate in the virtual memory
		nextSegment, diff_p_vaddr = self.getNextSegmentAndFreeSpace(segmentToExtend)

		# check if a segment exists directly after the segment to manipulate in the virtual memory
		if nextSegment == None: # segment directly after segment to manipulate does not exist in virtual memory

			# get memory address and offset in file of appended data
			newDataMemoryAddr = segmentToExtend.elfN_Phdr.p_vaddr + segmentToExtend.elfN_Phdr.p_memsz
			newDataOffset = segmentToExtend.elfN_Phdr.p_offset + segmentToExtend.elfN_Phdr.p_filesz

			# insert data
			for i in range(len(data)):
				self.data.insert((newDataOffset + i), data[i])

			# adjust offsets of all following section (for example symbol sections are often behind all segments)
			for section in self.sections:
				if section.elfN_shdr.sh_offset >= (segmentToExtend.elfN_Phdr.p_offset + segmentToExtend.elfN_Phdr.p_filesz):
					section.elfN_shdr.sh_offset += len(data)

			# extend size of data in file of the modifed segment
			segmentToExtend.elfN_Phdr.p_filesz += len(data)

			# extend size of data in memory of the modifed segment
			segmentToExtend.elfN_Phdr.p_memsz += len(data)					


		else: # segment directly after segment to manipulate exists in virtual memory

			# check if data to append fits
			if len(data) >= diff_p_vaddr:
				raise ValueError("Size of data to append: %d Size of memory space: %d" % (len(data), diff_p_vaddr))

			# p_offset and p_vaddr are congruend modulo alignment
			# for example:
			# p_align: 0x1000 (default for LOAD segment)
			# p_offset: 0x016f88
			# p_vaddr: 0x0805ff88
			# => 0x016f88 % 0x1000 = 0xf88
			# both must have 0xf88 at the end of the address

			# get how often the appended data fits in the alignment of the segment
			alignmentMultiplier = int(len(data) / segmentToExtend.elfN_Phdr.p_align) + 1

			# calculate the size to add to the offsets
			offsetAddition = alignmentMultiplier * segmentToExtend.elfN_Phdr.p_align 

			# adjust offsets of all following section
			for section in self.sections:
				if section.elfN_shdr.sh_offset >= nextSegment.elfN_Phdr.p_offset:
					section.elfN_shdr.sh_offset += offsetAddition

			# adjust offsets of following segments (ignore the directly followed segment)
			for segment in self.segments:
				if segment != segmentToExtend and segment != nextSegment:
					# use offset of the directly followed segment in order to ignore segments that lies within the segment to manipulate
					if segment.elfN_Phdr.p_offset > nextSegment.elfN_Phdr.p_offset:
						segment.elfN_Phdr.p_offset += offsetAddition

			# adjust offset of the directly following segment of the segment to manipulate
			nextSegment.elfN_Phdr.p_offset += offsetAddition

			# if program header table lies behind the segment to manipulate => move it
			if self.header.e_phoff > (segmentToExtend.elfN_Phdr.p_offset + segmentToExtend.elfN_Phdr.p_filesz):
				self.header.e_phoff += offsetAddition

			# if section header table lies behind the segment to manipulate => move it
			if self.header.e_shoff > (segmentToExtend.elfN_Phdr.p_offset + segmentToExtend.elfN_Phdr.p_filesz):
				self.header.e_shoff += offsetAddition

			# get memory address and offset in file of appended data
			newDataMemoryAddr = segmentToExtend.elfN_Phdr.p_vaddr + segmentToExtend.elfN_Phdr.p_memsz
			newDataOffset = segmentToExtend.elfN_Phdr.p_offset + segmentToExtend.elfN_Phdr.p_filesz	

			# insert data
			for i in range(len(data)):
				self.data.insert((newDataOffset + i), data[i])

			# fill the rest with 0x00 until the offset addition in the file is reached
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
			# addNewSection(newSectionName, newSectionType, newSectionFlag, newSectionAddr, newSectionOffset, newSectionSize, newSectionLink, newSectionInfo, newSectionAddrAlign, newSectionEntsize)
			self.addNewSection(newSectionName, SH_type.SHT_PROGBITS, (SH_flags.SHF_EXECINSTR | SH_flags.SHF_ALLOC), newDataMemoryAddr, newDataOffset, len(data), 0, 0, newSectionAddrAlign, 0)

		# if added data should extend an existing section => search this section and extend it
		if extendExistingSection and not addNewSection:
			for section in self.sections:
				# the end of an existing section in the virtual memory is generally equal
				# to the virtual memory address of the added data
				if (section.elfN_shdr.sh_addr + section.elfN_shdr.sh_size) == newDataMemoryAddr:
					# check if data is not appended to last section => use free space between segments for section 
					if diff_p_vaddr != None:
						# extend the existing section
						self.extendSection(section, diff_p_vaddr)
					else:
						# extend the existing section
						self.extendSection(section, len(data))

					break

		if not extendExistingSection and not addNewSection:
			print "NOTE: if appended data do not belong to a section they will not be seen by tools that interpret sections (like 'IDA 6.1.x' without the correct settings or 'strings' in the default configuration)."

		# return offset of appended data in file and address in memory
		return newDataOffset, newDataMemoryAddr
		



	# this function generates and adds a new section to the ELF file
	# return values: None
	def addNewSection(self, newSectionName, newSectionType, newSectionFlag, newSectionAddr, newSectionOffset, newSectionSize, newSectionLink, newSectionInfo, newSectionAddrAlign, newSectionEntsize):

		# get index in the string table of the name of the new section (use size of string table to just append new name to string table)
		newSectionStringTableIndex = self.sections[self.header.e_shstrndx].elfN_shdr.sh_size

		# generate new section object
		# generateNewSection(sectionName, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize)
		newsection = self.generateNewSection(newSectionName, newSectionStringTableIndex, newSectionType, newSectionFlag, newSectionAddr, newSectionOffset, newSectionSize, newSectionLink, newSectionInfo, newSectionAddrAlign, newSectionEntsize)

		# get position of new section
		positionNewSection = None
		for i in range(self.header.e_shnum):
			if (i+1) < self.header.e_shnum:
				if (self.sections[i].elfN_shdr.sh_offset < newSectionOffset 
				and self.sections[i+1].elfN_shdr.sh_offset > newSectionOffset):
					positionNewSection = i+1

					# if new section comes before string table section => adjust string table section index
					if positionNewSection <= self.header.e_shstrndx:
						self.header.e_shstrndx += 1
					break
		# insert new section at calculated position
		if positionNewSection == None:
			self.sections.append(newsection)
		else:
			self.sections.insert(positionNewSection, newsection)

		# section header table lies oft directly behind the string table
		# check if new section name would overwrite data of section header table
		# => move section header table
		if (self.header.e_shoff > (self.sections[self.header.e_shstrndx].elfN_shdr.sh_offset + self.sections[self.header.e_shstrndx].elfN_shdr.sh_size) 
		and self.header.e_shoff < (self.sections[self.header.e_shstrndx].elfN_shdr.sh_offset + self.sections[self.header.e_shstrndx].elfN_shdr.sh_size + len(newSectionName))):
			self.header.e_shoff += len(newSectionName)

		# add size of new name to string table
		self.sections[self.header.e_shstrndx].elfN_shdr.sh_size += len(newSectionName)

		# increase count of sections
		self.header.e_shnum += 1




	# this function extends the section size by the given size
	# return values: None
	def extendSection(self, sectionToExtend, size):
		sectionToExtend.elfN_shdr.sh_size += size




	# this function searches for a executable segment from type PT_LOAD in which the data fits
	# return values: (class Segment) manipulated segment, (int) offset in file of appended data, (int) address in memory of appended data
	def appendDataToExecutableSegment(self, data, addNewSection=False, newSectionName=None, extendExistingSection=False):

		# get all executable segments from type PT_LOAD
		possibleSegments = list()
		for segment in self.segments:
			if (segment.elfN_Phdr.p_flags & P_flags.PF_X) == 1 and segment.elfN_Phdr.p_type == P_type.PT_LOAD:
				possibleSegments.append(segment)

		# find space for data in all possible executable segments
		found = False
		for possibleSegment in possibleSegments:
			diff_p_vaddr = None
			# find segment that comes directly after the segment to manipulate in the virtual memory
			# and get the free memory space in between
			for i in range(len(self.segments)):
				if self.segments[i] != possibleSegment:
					if (self.segments[i].elfN_Phdr.p_vaddr - (possibleSegment.elfN_Phdr.p_vaddr + possibleSegment.elfN_Phdr.p_memsz)) > 0:
						if diff_p_vaddr == None or (self.segments[i].elfN_Phdr.p_vaddr - (possibleSegment.elfN_Phdr.p_vaddr + possibleSegment.elfN_Phdr.p_memsz)) < diff_p_vaddr:
							diff_p_vaddr = self.segments[i].elfN_Phdr.p_vaddr - (possibleSegment.elfN_Phdr.p_vaddr + possibleSegment.elfN_Phdr.p_memsz)
				else: # get position in list of possible segment
					segmentNumber = i
			# check if data to append fits in space
			if diff_p_vaddr > len(data):
				found = True
				break
		if not found:
			raise ValueError("Size of data to append: %d Not enough space after existing executable segment found." % len(data))

		# append data to segment
		newDataOffset, newDataMemoryAddr = self.appendDataToSegment(data, segmentNumber, addNewSection=addNewSection, newSectionName=newSectionName, extendExistingSection=extendExistingSection)

		# return manipulated segment, offset of appended data in file and memory address of appended data
		return self.segments[segmentNumber], newDataOffset, newDataMemoryAddr




	# this function gets the next segment of the given one and the free space in memory in between
	# return values: (class Segment) next segment, (int) free space; both None if no following segment was found
	def getNextSegmentAndFreeSpace(self, segmentToSearch):

		# find segment that comes directly after the segment to manipulate in the virtual memory
		diff_p_vaddr = None
		nextSegment = None
		for segment in self.segments:
			if segment != segmentToSearch:
				if (segment.elfN_Phdr.p_vaddr - (segmentToSearch.elfN_Phdr.p_vaddr + segmentToSearch.elfN_Phdr.p_memsz)) > 0:
					if diff_p_vaddr == None or (segment.elfN_Phdr.p_vaddr - (segmentToSearch.elfN_Phdr.p_vaddr + segmentToSearch.elfN_Phdr.p_memsz)) < diff_p_vaddr:
						diff_p_vaddr = segment.elfN_Phdr.p_vaddr - (segmentToSearch.elfN_Phdr.p_vaddr + segmentToSearch.elfN_Phdr.p_memsz)
						nextSegment = segment

		# return nextSegment and free space
		return nextSegment, diff_p_vaddr




	# this function is a wrapper function for getNextSegmentAndFreeSpace(segmentToSearch)
	# which returns only the free space in memory after the segment
	# return values: (int) free space; None if no following segment was found
	def getFreeSpaceAfterSegment(self, segmentToSearch):
		nextSegment, diff_p_vaddr = self.getNextSegmentAndFreeSpace(segmentToSearch)
		return diff_p_vaddr




	# this function removes all section header entries
	# return values: None
	def removeSectionHeaderTable(self):
		self.header.e_shoff = 0
		self.header.e_shnum = 0
		self.header.e_shentsize = 0
		self.header.e_shstrndx = Shstrndx.SHN_UNDEF
		self.sections = list()




	# this function overwrites data on the given offset 
	# return values: None
	def writeDataToFileOffset(self, offset, data, force=False):

		# get the segment to which the changed data belongs to
		segmentToManipulate = None
		for segment in self.segments:
			if (offset > segment.elfN_Phdr.p_offset
			and offset < (segment.elfN_Phdr.p_offset + segment.elfN_Phdr.p_filesz)):
				segmentToManipulate = segment
				break

		# check if segment was found
		if (segmentToManipulate == None 
			and force == False):
			raise ValueError('Segment with offset 0x%x not found (use "force=True" to ignore this check).' % offset)

		# calculate position of data to manipulate in segment
		dataPosition = offset - segmentToManipulate.elfN_Phdr.p_offset

		# check if data to manipulate fits in segment
		if (len(data) > (segmentToManipulate.elfN_Phdr.p_filesz - dataPosition)
			and force == False):
			raise ValueError('Size of data to manipulate: %d Not enough space in segment (Available: %d; use "force=True" to ignore this check).' % (len(data), (segmentToManipulate.elfN_Phdr.p_filesz - offset)))

		# change data
		for i in range(len(data)):
			self.data[offset + i] = data[i]




	# this function converts the virtual memory address to the file offset
	# return value: (int) offset in file (or None if not found)
	def virtualMemoryAddrToFileOffset(self, memoryAddr):

		# get the segment to which the virtual memory address belongs to
		foundSegment = None
		for segment in self.segments:
			if (memoryAddr > segment.elfN_Phdr.p_vaddr
				and memoryAddr < (segment.elfN_Phdr.p_vaddr + segment.elfN_Phdr.p_memsz)):
				foundSegment = segment
				break

		# check if segment was found
		if foundSegment == None:
			return None

		# check if file is mapped 1:1 to memory
		if foundSegment.elfN_Phdr.p_filesz != foundSegment.elfN_Phdr.p_memsz:
			# check if the memory address relative to the virtual memory address of the segment lies within the file size of the segment
			if ((memoryAddr - segment.elfN_Phdr.p_vaddr) > 0
				and (memoryAddr - segment.elfN_Phdr.p_vaddr) < foundSegment.elfN_Phdr.p_filesz):
					pass
			else:
				raise ValueError("Can not convert virtual memory address to file offset.")

		relOffset = memoryAddr - foundSegment.elfN_Phdr.p_vaddr
		return foundSegment.elfN_Phdr.p_offset + relOffset




	# this function converts the file offset to the virtual memory address
	# return value: (int) virtual memory address (or None if not found)
	def fileOffsetToVirtualMemoryAddr(self, offset):

		# get the segment to which the file offset belongs to
		foundSegment = None
		for segment in self.segments:
			if (offset > segment.elfN_Phdr.p_offset
			and offset < (segment.elfN_Phdr.p_offset + segment.elfN_Phdr.p_filesz)):
				foundSegment = segment
				break

		# check if segment was found
		if foundSegment == None:
			return None

		# check if file is mapped 1:1 to memory
		if foundSegment.elfN_Phdr.p_filesz != foundSegment.elfN_Phdr.p_memsz:
			raise ValueError("Data not mapped 1:1 from file to memory. Can not convert virtual memory address to file offset.")

		return foundSegment.elfN_Phdr.p_vaddr + offset




	# this function overwrites an entry in the got (global offset table) in the file
	# return values: None
	def modifyGotEntryAddr(self, name, memoryAddr):

		# search for name in jump relocation entries
		entryToModify = None
		for jmpEntry in self.jumpRelocationEntries:
			if jmpEntry.name == name:
				entryToModify = jmpEntry
				break
		if entryToModify == None:
			raise ValueError('Jump relocation entry with the name "%s" was not found.' % name)

		# calculate file offset of got 
		entryOffset = self.virtualMemoryAddrToFileOffset(entryToModify.r_offset)

		# generate list with new memory address for got
		# for 32 bit systems only
		newGotAddr = list()
		newGotAddr.append(chr((memoryAddr & 0xff)))
		newGotAddr.append((chr((memoryAddr >> 8) & 0xff)))
		newGotAddr.append((chr((memoryAddr >> 16) & 0xff)))
		newGotAddr.append((chr((memoryAddr >> 24) & 0xff)))

		# overwrite old offset
		self.writeDataToFileOffset(entryOffset, newGotAddr)




	# this function gets the value of the got (global offset table) entry (a memory address to jump to)
	# return values: (int) value (memory address) of got entry
	def getValueOfGotEntry(self, name):

		# search for name in jump relocation entries
		entryToModify = None
		for jmpEntry in self.jumpRelocationEntries:
			if jmpEntry.name == name:
				entryToModify = jmpEntry
				break
		if entryToModify == None:
			raise ValueError('Jump relocation entry with the name "%s" was not found.' % name)

		# calculate file offset of got 
		entryOffset = self.virtualMemoryAddrToFileOffset(entryToModify.r_offset)

		return ((ord(self.data[entryOffset + 3])<<24) + (ord(self.data[entryOffset + 2])<<16) + (ord(self.data[entryOffset + 1])<<8)+ ord(self.data[entryOffset]))




	# this function gets the memory address of the got (global offset table) entry
	# return values: (int) memory address of got entry
	def getMemAddrOfGotEntry(self, name):

		# search for name in jump relocation entries
		entryToSearch = None
		for jmpEntry in self.jumpRelocationEntries:
			if jmpEntry.name == name:
				entryToSearch = jmpEntry
				break
		if entryToSearch == None:
			raise ValueError('Jump relocation entry with the name "%s" was not found.' % name)

		return entryToSearch.r_offset
