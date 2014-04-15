#!/usr/bin/python

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

manipulatedSegment, newDataOffset, newDataMemoryAddr \
	= test.appendDataToExecutableSegment(dummyData)

print "Offset of new data: 0x%x" % newDataOffset
print "Virtual memory addr of new data: 0x%x" % newDataMemoryAddr

'''
first 28 bytes of "ls" entrypoint

08049bb0 <.text>:
8049bb0:       31 ed                   xor    ebp,ebp
8049bb2:       5e                      pop    esi
8049bb3:       89 e1                   mov    ecx,esp
8049bb5:       83 e4 f0                and    esp,0xfffffff0
8049bb8:       50                      push   eax
8049bb9:       54                      push   esp
8049bba:       52                      push   edx
8049bbb:       68 50 ac 05 08          push   0x805ac50
8049bc0:       68 60 ac 05 08          push   0x805ac60
8049bc5:       51                      push   ecx
8049bc6:       56                      push   esi
8049bc7:       68 c0 fb 04 08          push   0x804fbc0
'''


copiedBytesFromEntry = 8

entryPointOffset = test.virtualMemoryAddrToFileOffset(originalEntry)
entryPointData = list()
for i in range(copiedBytesFromEntry):
	entryPointData.append(test.data[entryPointOffset + i])


testData = list()

# store address of newDataMemoryAddr + 4 at newDataMemoryAddr 
# (for instruction "mov ecx, [newDataMemoryAddr]"")
testData.append(chr(((newDataMemoryAddr+4) & 0xff)))
testData.append((chr(((newDataMemoryAddr+4) >> 8) & 0xff)))
testData.append((chr(((newDataMemoryAddr+4) >> 16) & 0xff)))
testData.append((chr(((newDataMemoryAddr+4) >> 24) & 0xff)))

# copy original entrypoint data (these instructions are executed 
# first when control flow is altered)
for i in range(len(entryPointData)):
	testData.append(entryPointData[i])

# calculate relative jump from current position to 
# entrypoint + copiedBytesFromEntry
# formula: 0 - (sourceAddress  - targetAddress) - 5
jumpTarget = c_uint(0 - ((newDataMemoryAddr + len(testData)) 
	- ((originalEntry + copiedBytesFromEntry))) - 5 ).value
testData.append("\xE9") # JMP rel32
testData.append(chr((jumpTarget & 0xff)))
testData.append((chr((jumpTarget >> 8) & 0xff)))
testData.append((chr((jumpTarget >> 16) & 0xff)))
testData.append((chr((jumpTarget >> 24) & 0xff)))

# overwrite dummy data
test.writeDataToFileOffset(newDataOffset, testData)


hookData = list()

# mov ecx, [newDataMemoryAddr]
hookData.append("\x8B")
hookData.append("\x0D")
hookData.append(chr((newDataMemoryAddr & 0xff)))
hookData.append((chr((newDataMemoryAddr >> 8) & 0xff)))
hookData.append((chr((newDataMemoryAddr >> 16) & 0xff)))
hookData.append((chr((newDataMemoryAddr >> 24) & 0xff)))

# jmp ecx
hookData.append("\xFF")
hookData.append("\xE1")

# fill rest of missing data with nops
while len(hookData) < copiedBytesFromEntry:
	# nop
	hookData.append("\x90")


test.writeDataToFileOffset(entryPointOffset, hookData)

#test.removeSectionHeaderTable()

test.writeElf("test_ls")

print
