#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# github: https://github.com/sqall01
# 
# Licensed under the GNU Public License, version 2.

from ctypes import c_uint
from ZwoELF import ElfParser, D_tag, SH_type, SH_flags, P_type, P_flags
import sys
import random
import time


def replaceSymbolString(dynStrData, oldSymbol, newSymbol):

	print "Replacing '%s' with '%s'" % (oldSymbol, newSymbol)

	# check if new symbol name is longer thant old symbol name
	# (not possible without rewriting the complete binary)
	if len(oldSymbol) < len(newSymbol):
		raise ValueError("New symbol not longer than old symbol name.")

	# generate string from the bytearray to search easier for old symbol name
	dataString = ""
	for i in range(len(dynStrData)):
		dataString += chr(dynStrData[i])

	# search old symbol with trailing and leading null termination
	positionOfSymbol = dataString.find("\x00" + oldSymbol + "\x00")
	if positionOfSymbol == -1:
		raise ValueError("Old symbol name was not found.")
	positionOfSymbol += 1

	# when the old symbol name is longer than the new one
	# fill the gab with null bytes
	for i in range((len(oldSymbol) - len(newSymbol))):
		newSymbol += "\x00"

	# replace old symbol name with new one
	for i in range(len(oldSymbol)):
		dynStrData[positionOfSymbol + i] = newSymbol[i]

	return dynStrData



try:
	inputFile = sys.argv[1]
	outputFile = sys.argv[2]
except:
	print('usage: {} <input file> <output file>'.format(sys.argv[0]))
	print('')
	sys.exit(1)

# CHANGE HERE WHAT YOU WANT TO EXCHANGE
# list of symbols to replace [(oldsymbol, newsymbol)]
#symbolsToReplace = [("__libc_start_main", "__libc_foo"), ("malloc", "flux")]
symbolsToReplace = [("printf", "fputs"), ("system", "printf"),
	("strncmp", "strcmp")]











parsedFile = ElfParser(inputFile)

# we want to add the forged dynamic string table behind the executable
# loaded segment => get this segment
segmentToExtend = None
for segment in parsedFile.segments:
	if (segment.elfN_Phdr.p_type == P_type.PT_LOAD and
		(segment.elfN_Phdr.p_flags & P_flags.PF_X) == 0x1):
		segmentToExtend = segment
if segmentToExtend is None:
	print "No loadable segment was found."
	sys.exit(0)

# get dynamic string section
dynStrSection = None
for section in parsedFile.sections:
	if section.sectionName == ".dynstr":
		dynStrSection = section
		break
if dynStrSection is None:
	print "No .dynstr section was found."
	sys.exit(0)

# get data of original dynamic string table 
dynStrOffsetStart = dynStrSection.elfN_shdr.sh_offset
dynStrOffsetEnd = dynStrSection.elfN_shdr.sh_offset \
	+ dynStrSection.elfN_shdr.sh_size
dynStrSectionData = parsedFile.data[dynStrOffsetStart:dynStrOffsetEnd]

# calculate offset of new dynamic string table
newDynStrOffset = segmentToExtend.elfN_Phdr.p_offset \
	+ segmentToExtend.elfN_Phdr.p_filesz

# generate random size of data that is added before new dynamic string table
random.seed(time.time()) # not important to be unpredictable
randomPrefixData = random.randint(0, 1000)

# calculate size of data block that has to be inserted so the new dynamic
# string table fits after the executable load segment
offsetAddition = segmentToExtend.elfN_Phdr.p_align
while (len(dynStrSectionData) + randomPrefixData) > offsetAddition:
	offsetAddition += segmentToExtend.elfN_Phdr.p_align
print "Needed data to inject: %d bytes" % offsetAddition

nextSegment, freeSpace = parsedFile.getNextSegmentAndFreeSpace(
	segmentToExtend)

if nextSegment is None:
	raise NotImplementedError("Appending data to the end of the file "
		+ "not implemented yet.")

# adjust offsets of all following section
for section in parsedFile.sections:
	if (section.elfN_shdr.sh_offset
		>= nextSegment.elfN_Phdr.p_offset):
		section.elfN_shdr.sh_offset += offsetAddition

# adjust offsets of following segments
# (ignore the directly followed segment)
for segment in parsedFile.segments:
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
if (parsedFile.header.e_phoff > (segmentToExtend.elfN_Phdr.p_offset
	+ segmentToExtend.elfN_Phdr.p_filesz)):
	parsedFile.header.e_phoff += offsetAddition

# if section header table lies behind the segment to manipulate
# => move it
if (parsedFile.header.e_shoff > (segmentToExtend.elfN_Phdr.p_offset
	+ segmentToExtend.elfN_Phdr.p_filesz)):
	parsedFile.header.e_shoff += offsetAddition

# replace all symbols
for symbolTuple in symbolsToReplace:
	dynStrSectionData = replaceSymbolString(dynStrSectionData,
	symbolTuple[0], symbolTuple[1])

# first insert the random prefix data
for i in range(randomPrefixData):
	parsedFile.data.insert((newDynStrOffset + i), chr(random.randint(0, 255)))

# second insert dynamic string table data
for i in range(len(dynStrSectionData)):
	parsedFile.data.insert((newDynStrOffset + randomPrefixData + i),
		dynStrSectionData[i])

# third fill gab to next segment with random data
for i in range(offsetAddition - len(dynStrSectionData) - randomPrefixData):
	parsedFile.data.insert((newDynStrOffset + randomPrefixData
		+ len(dynStrSectionData) + i), chr(random.randint(0, 255)))

print "Offset of new dynamic string table: 0x%x" \
	% (newDynStrOffset + randomPrefixData)

# set new dynamic string section offset
dynStrSection.elfN_shdr.sh_offset = newDynStrOffset + randomPrefixData

# write file
parsedFile.writeElf(outputFile)