#!/usr/bin/python

# written by sqall
# twitter: https://twitter.com/sqall01
# blog: http://blog.h4des.org
# github: https://github.com/sqall01
# 
# Licensed under the GNU Public License, version 2.

from ctypes import c_uint
from ZwoELF import ElfParser

x86File = "ls"


print "Manipulating: %s" % x86File
test = ElfParser(x86File)

freeSpace = test.getFreeSpaceAfterSegment(test.segments[2])
print "Free space: %d Bytes " % freeSpace

# get original entry point
originalEntry = test.header.e_entry


dummyData = list()
for i in range(freeSpace-1):
	#dummyData.append("\x00")
	dummyData.append("\x41")

#manipulatedSegment, newDataOffset, newDataMemoryAddr 
# = test.appendDataToExecutableSegment(dummyData, 
# addNewSection=True, newSectionName=".blahblub")
# manipulatedSegment, newDataOffset, newDataMemoryAddr 
# = test.appendDataToExecutableSegment(dummyData, extendExistingSection=True)
manipulatedSegment, newDataOffset, newDataMemoryAddr \
	= test.appendDataToExecutableSegment(dummyData)

print "Offset of new data: 0x%x" % newDataOffset
print "Virtual memory addr of new data: 0x%x" % newDataMemoryAddr

# jump from newDataMemoryAddr to originalEntry
# 0 - (newDataMemoryAddr - originalEntry) - 5
jumpTarget = c_uint(0 - (newDataMemoryAddr - originalEntry) - 5).value

# jump from new code to old entry point
testData = list()
testData.append("\xE9") # JMP rel32
testData.append(chr((jumpTarget & 0xff)))
testData.append((chr((jumpTarget >> 8) & 0xff)))
testData.append((chr((jumpTarget >> 16) & 0xff)))
testData.append((chr((jumpTarget >> 24) & 0xff)))

# overwrite dummy data
test.writeDataToFileOffset(newDataOffset, testData)

# change entry point to new data
test.header.e_entry = newDataMemoryAddr

test.writeElf("test_" + x86File)

print "\n\n-----------\n\n"
