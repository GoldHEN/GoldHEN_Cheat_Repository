#!/usr/bin/env python
'''

PS4 Module Loader by SocraticBliss (R)

Major Thanks to...
# aerosoul
# balika011
# Znullptr
# Pablo (kozarovv)
# ChendoChap
# xyz
# CelesteBlue
# kiwidogg
# motoharu
# noname120
# flatz
# Team Reswitched

Extra Special Thanks for telling me my program sucks...
# zecoxao

ps4_module.py: IDA loader for reading Sony PlayStation(R) 4 Module files

'''

from idaapi import *
from idc import *

import csv
import idaapi
import idc
import shutil
import struct

class Binary:

    __slots__ = ('EI_MAGIC', 'EI_CLASS', 'EI_DATA', 'EI_VERSION',
                 'EI_OSABI', 'EI_PADDING', 'EI_ABIVERSION', 'EI_SIZE',
                 'E_TYPE', 'E_MACHINE', 'E_VERSION', 'E_START_ADDR',
                 'E_PHT_OFFSET', 'E_SHT_OFFSET', 'E_FLAGS', 'E_SIZE',
                 'E_PHT_SIZE', 'E_PHT_COUNT', 'E_SHT_SIZE', 'E_SHT_COUNT',
                 'E_SHT_INDEX', 'E_SEGMENTS', 'E_SECTIONS')
    
    # Elf Types
    ET_NONE                   = 0x0
    ET_REL                    = 0x1
    ET_EXEC                   = 0x2
    ET_DYN                    = 0x3
    ET_CORE                   = 0x4
    ET_SCE_EXEC               = 0xFE00
    ET_SCE_REPLAY_EXEC        = 0xFE01
    ET_SCE_RELEXEC            = 0xFE04
    ET_SCE_STUBLIB            = 0xFE0C
    ET_SCE_DYNEXEC            = 0xFE10
    ET_SCE_DYNAMIC            = 0xFE18
    ET_LOPROC                 = 0xFF00
    ET_HIPROC                 = 0xFFFF
    
    # Elf Architecture
    EM_X86_64                 = 0x3E
    
    def __init__(self, f):
    
        f.seek(0)
        
        self.EI_MAGIC         = struct.unpack('4s', f.read(4))[0]
        self.EI_CLASS         = struct.unpack('<B', f.read(1))[0]
        self.EI_DATA          = struct.unpack('<B', f.read(1))[0]
        self.EI_VERSION       = struct.unpack('<B', f.read(1))[0]
        self.EI_OSABI         = struct.unpack('<B', f.read(1))[0]
        self.EI_ABIVERSION    = struct.unpack('<B', f.read(1))[0]
        self.EI_PADDING       = struct.unpack('6x', f.read(6))
        self.EI_SIZE          = struct.unpack('<B', f.read(1))[0]
        
        # Elf Properties
        self.E_TYPE           = struct.unpack('<H', f.read(2))[0]
        self.E_MACHINE        = struct.unpack('<H', f.read(2))[0]
        self.E_VERSION        = struct.unpack('<I', f.read(4))[0]
        self.E_START_ADDR     = struct.unpack('<Q', f.read(8))[0]
        self.E_PHT_OFFSET     = struct.unpack('<Q', f.read(8))[0]
        self.E_SHT_OFFSET     = struct.unpack('<Q', f.read(8))[0]
        self.E_FLAGS          = struct.unpack('<I', f.read(4))[0]
        self.E_SIZE           = struct.unpack('<H', f.read(2))[0]
        self.E_PHT_SIZE       = struct.unpack('<H', f.read(2))[0]
        self.E_PHT_COUNT      = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_SIZE       = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_COUNT      = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_INDEX      = struct.unpack('<H', f.read(2))[0]
        
        # Prevent Other Binaries
        if self.E_MACHINE != Binary.EM_X86_64:
            return None
        
        f.seek(self.E_PHT_OFFSET)
        
        # Elf Program Header Table
        Binary.E_SEGMENTS = [Segment(f) for entry in range(self.E_PHT_COUNT)]
        
        f.seek(self.E_SHT_OFFSET)
        
        # Elf Section Header Table
        Binary.E_SECTIONS = [Section(f) for entry in range(self.E_SHT_COUNT)]
    
    def type(self):
    
        return {
            Binary.ET_NONE            : 'None',
            Binary.ET_REL             : 'Relocatable',
            Binary.ET_EXEC            : 'Executable',
            Binary.ET_DYN             : 'Shared Object',
            Binary.ET_CORE            : 'Core Dump',
            Binary.ET_SCE_EXEC        : 'Main Module',
            Binary.ET_SCE_REPLAY_EXEC : 'Replay Module',
            Binary.ET_SCE_RELEXEC     : 'Relocatable PRX',
            Binary.ET_SCE_STUBLIB     : 'Stub Library',
            Binary.ET_SCE_DYNEXEC     : 'Main Module - ASLR',
            Binary.ET_SCE_DYNAMIC     : 'Shared Object PRX',
        }.get(self.E_TYPE, 'Missing Program Type!!!')
    
    def procomp(self, processor, pointer, til):
    
        # Processor Type
        idc.set_processor_type(processor, SETPROC_LOADER)
        
        # Compiler Attributes
        idc.set_inf_attr(INF_COMPILER, COMP_GNU)
        idc.set_inf_attr(INF_MODEL, pointer)
        idc.set_inf_attr(INF_SIZEOF_BOOL, 0x1)
        idc.set_inf_attr(INF_SIZEOF_LONG, 0x8)
        idc.set_inf_attr(INF_SIZEOF_LDBL, 0x10)
        
        # Type Library
        idc.add_default_til(til)
        
        # Loader Flags
        #idc.set_inf_attr(INF_LFLAGS, LFLG_64BIT)
        
        # Assume GCC3 names
        idc.set_inf_attr(INF_DEMNAMES, DEMNAM_GCC3 | DEMNAM_NAME)
        
        # Analysis Flags 
        # (unchecked) Delete instructions with no xrefs
        # (unchecked) Coagulate data segments in the final pass
        idc.set_inf_attr(INF_AF, 0xDFFFFFDF)
        
        # Return Bitsize
        return self.EI_CLASS
    

class Segment:

    __slots__ = ('TYPE', 'FLAGS', 'OFFSET', 'MEM_ADDR',
                 'FILE_ADDR', 'FILE_SIZE', 'MEM_SIZE', 'ALIGNMENT')
    
    # Segment Types
    PT_NULL                = 0x0
    PT_LOAD                = 0x1
    PT_DYNAMIC             = 0x2
    PT_INTERP              = 0x3
    PT_NOTE                = 0x4
    PT_SHLIB               = 0x5
    PT_PHDR                = 0x6
    PT_TLS                 = 0x7
    PT_NUM                 = 0x8
    PT_SCE_DYNLIBDATA      = 0x61000000
    PT_SCE_PROCPARAM       = 0x61000001
    PT_SCE_MODULEPARAM     = 0x61000002
    PT_SCE_RELRO           = 0x61000010
    PT_GNU_EH_FRAME        = 0x6474E550
    PT_GNU_STACK           = 0x6474E551
    PT_SCE_COMMENT         = 0x6FFFFF00
    PT_SCE_LIBVERSION      = 0x6FFFFF01
    PT_HIOS                = 0x6FFFFFFF
    PT_LOPROC              = 0x70000000
    PT_SCE_SEGSYM          = 0x700000A8
    PT_HIPROC              = 0x7FFFFFFF
    
    # Segment Alignments
    AL_NONE                = 0x0
    AL_BYTE                = 0x1
    AL_WORD                = 0x2
    AL_DWORD               = 0x4
    AL_QWORD               = 0x8
    AL_PARA                = 0x10
    AL_4K                  = 0x4000
    
    def __init__(self, f):
    
        self.TYPE      = struct.unpack('<I', f.read(4))[0]
        self.FLAGS     = struct.unpack('<I', f.read(4))[0]
        self.OFFSET    = struct.unpack('<Q', f.read(8))[0]
        self.MEM_ADDR  = struct.unpack('<Q', f.read(8))[0]
        self.FILE_ADDR = struct.unpack('<Q', f.read(8))[0]
        self.FILE_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.MEM_SIZE  = struct.unpack('<Q', f.read(8))[0]
        self.ALIGNMENT = struct.unpack('<Q', f.read(8))[0]
    
    def alignment(self):
    
        return {
            Segment.AL_NONE            : saAbs,
            Segment.AL_BYTE            : saRelByte,
            Segment.AL_WORD            : saRelWord,
            Segment.AL_DWORD           : saRelDble,
            Segment.AL_QWORD           : saRelQword,
            Segment.AL_PARA            : saRelPara,
            Segment.AL_4K              : saRel4K,
        }.get(self.ALIGNMENT, saRel_MAX_ALIGN_CODE)
    
    def flags(self):
    
        return self.FLAGS & 0xF
    
    def name(self):
    
        return {
            Segment.PT_NULL            : 'NULL',
            Segment.PT_LOAD            : 'CODE' if self.flags() == (SEGPERM_EXEC | SEGPERM_READ) else 'DATA',
            Segment.PT_DYNAMIC         : 'DYNAMIC',
            Segment.PT_INTERP          : 'INTERP',
            Segment.PT_NOTE            : 'NOTE',
            Segment.PT_SHLIB           : 'SHLIB',
            Segment.PT_PHDR            : 'PHDR',
            Segment.PT_TLS             : 'TLS',
            Segment.PT_NUM             : 'NUM',
            Segment.PT_SCE_DYNLIBDATA  : 'SCE_DYNLIBDATA',
            Segment.PT_SCE_PROCPARAM   : 'SCE_PROCPARAM',
            Segment.PT_SCE_MODULEPARAM : 'SCE_MODULEPARAM',
            Segment.PT_SCE_RELRO       : 'SCE_RELRO',
            Segment.PT_GNU_EH_FRAME    : 'GNU_EH_FRAME',
            Segment.PT_GNU_STACK       : 'GNU_STACK',
            Segment.PT_SCE_COMMENT     : 'SCE_COMMENT',
            Segment.PT_SCE_LIBVERSION  : 'SCE_LIBVERSION',
        }.get(self.TYPE, 'UNK')
    
    def struct(self, name, members, location = 0x0):
    
        if self.FLAGS > 7:
            return idc.get_struc_id(name)
        
        entry = idc.add_struc(BADADDR, name, False)
        
        for (member, comment, size) in members:
            flags = idaapi.get_flags_by_size(size)
            
            if member in ['addend', 'offset']:
                idc.add_struc_member(entry, member, location, flags + FF_0OFF, BADADDR, size, BADADDR, 0, REF_OFF64)
            else:
                idc.add_struc_member(entry, member, location, flags, BADADDR, size)
            
            idc.set_member_cmt(entry, location, comment, False)
            location += size
        
        return entry
    
    def type(self):
    
        return {
            Segment.PT_LOAD            : 'CODE' if self.flags() == (SEGPERM_EXEC | SEGPERM_READ) else 'DATA',
            Segment.PT_DYNAMIC         : 'DATA',
            Segment.PT_INTERP          : 'CONST',
            Segment.PT_NOTE            : 'CONST',
            Segment.PT_PHDR            : 'CODE',
            Segment.PT_TLS             : 'BSS',
            Segment.PT_SCE_DYNLIBDATA  : 'CONST',
            Segment.PT_SCE_PROCPARAM   : 'CONST',
            Segment.PT_SCE_MODULEPARAM : 'CONST',
            Segment.PT_SCE_RELRO       : 'DATA',
            Segment.PT_GNU_EH_FRAME    : 'CONST',
            Segment.PT_GNU_STACK       : 'DATA',
        }.get(self.TYPE, 'UNK')
    

class Section:
    
    __slots__ = ('NAME', 'TYPE', 'FLAGS', 'MEM_ADDR',
                 'OFFSET', 'FILE_SIZE', 'LINK', 'INFO',
                 'ALIGNMENT', 'FSE_SIZE')
    
    def __init__(self, f):
    
        self.NAME      = struct.unpack('<I', f.read(4))[0]
        self.TYPE      = struct.unpack('<I', f.read(4))[0]
        self.FLAGS     = struct.unpack('<Q', f.read(8))[0]
        self.MEM_ADDR  = struct.unpack('<Q', f.read(8))[0]
        self.OFFSET    = struct.unpack('<Q', f.read(8))[0]
        self.FILE_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.LINK      = struct.unpack('<I', f.read(4))[0]
        self.INFO      = struct.unpack('<I', f.read(4))[0]
        self.ALIGNMENT = struct.unpack('<Q', f.read(8))[0]
        self.FSE_SIZE  = struct.unpack('<Q', f.read(8))[0]
    

class Dynamic:
    
    __slots__ = ('TAG', 'VALUE', 'ID', 'VERSION_MAJOR', 'VERSION_MINOR', 'INDEX')
    
    # Dynamic Tags
    (DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB,
    DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI,
    DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL, DT_RELSZ, DT_RELENT, DT_PLTREL,
    DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW, DT_INIT_ARRAY, DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS, DT_ENCODING, DT_PREINIT_ARRAY,
    DT_PREINIT_ARRAYSZ)         = range(0x22)
    DT_SCE_IDTABENTSZ           = 0x61000005
    DT_SCE_FINGERPRINT          = 0x61000007
    DT_SCE_ORIGINAL_FILENAME    = 0x61000009
    DT_SCE_MODULE_INFO          = 0x6100000D
    DT_SCE_NEEDED_MODULE        = 0x6100000F
    DT_SCE_MODULE_ATTR          = 0x61000011
    DT_SCE_EXPORT_LIB           = 0x61000013
    DT_SCE_IMPORT_LIB           = 0x61000015
    DT_SCE_EXPORT_LIB_ATTR      = 0x61000017
    DT_SCE_IMPORT_LIB_ATTR      = 0x61000019
    DT_SCE_STUB_MODULE_NAME     = 0x6100001D
    DT_SCE_STUB_MODULE_VERSION  = 0x6100001F
    DT_SCE_STUB_LIBRARY_NAME    = 0x61000021
    DT_SCE_STUB_LIBRARY_VERSION = 0x61000023
    DT_SCE_HASH                 = 0x61000025
    DT_SCE_PLTGOT               = 0x61000027
    DT_SCE_JMPREL               = 0x61000029
    DT_SCE_PLTREL               = 0x6100002B
    DT_SCE_PLTRELSZ             = 0x6100002D
    DT_SCE_RELA                 = 0x6100002F
    DT_SCE_RELASZ               = 0x61000031
    DT_SCE_RELAENT              = 0x61000033
    DT_SCE_STRTAB               = 0x61000035
    DT_SCE_STRSZ                = 0x61000037
    DT_SCE_SYMTAB               = 0x61000039
    DT_SCE_SYMENT               = 0x6100003B
    DT_SCE_HASHSZ               = 0x6100003D
    DT_SCE_SYMTABSZ             = 0x6100003F
    DT_SCE_HIOS                 = 0x6FFFF000
    DT_GNU_HASH                 = 0x6FFFFEF5
    DT_VERSYM                   = 0x6FFFFFF0
    DT_RELACOUNT                = 0x6FFFFFF9
    DT_RELCOUNT                 = 0x6FFFFFFA
    DT_FLAGS_1                  = 0x6FFFFFFB
    DT_VERDEF                   = 0x6FFFFFFC
    DT_VERDEFNUM                = 0x6FFFFFFD
    
    def __init__(self, f):
    
        self.TAG   = struct.unpack('<Q', f.read(8))[0]
        self.VALUE = struct.unpack('<Q', f.read(8))[0]
    
    def tag(self):
    
        return {
            Dynamic.DT_NULL                     : 'DT_NULL',
            Dynamic.DT_NEEDED                   : 'DT_NEEDED',
            Dynamic.DT_PLTRELSZ                 : 'DT_PLTRELSZ',
            Dynamic.DT_PLTGOT                   : 'DT_PLTGOT',
            Dynamic.DT_HASH                     : 'DT_HASH',
            Dynamic.DT_STRTAB                   : 'DT_STRTAB',
            Dynamic.DT_SYMTAB                   : 'DT_SYMTAB',
            Dynamic.DT_RELA                     : 'DT_RELA',
            Dynamic.DT_RELASZ                   : 'DT_RELASZ',
            Dynamic.DT_RELAENT                  : 'DT_RELAENT',
            Dynamic.DT_STRSZ                    : 'DT_STRSZ',
            Dynamic.DT_SYMENT                   : 'DT_SYMENT',
            Dynamic.DT_INIT                     : 'DT_INIT',
            Dynamic.DT_FINI                     : 'DT_FINI',
            Dynamic.DT_SONAME                   : 'DT_SONAME',
            Dynamic.DT_RPATH                    : 'DT_RPATH',
            Dynamic.DT_SYMBOLIC                 : 'DT_SYMBOLIC',
            Dynamic.DT_REL                      : 'DT_REL',
            Dynamic.DT_RELSZ                    : 'DT_RELSZ',
            Dynamic.DT_RELENT                   : 'DT_RELENT',
            Dynamic.DT_PLTREL                   : 'DT_PLTREL',
            Dynamic.DT_DEBUG                    : 'DT_DEBUG',
            Dynamic.DT_TEXTREL                  : 'DT_TEXTREL',
            Dynamic.DT_JMPREL                   : 'DT_JMPREL',
            Dynamic.DT_BIND_NOW                 : 'DT_BIND_NOW',
            Dynamic.DT_INIT_ARRAY               : 'DT_INIT_ARRAY',
            Dynamic.DT_FINI_ARRAY               : 'DT_FINI_ARRAY',
            Dynamic.DT_INIT_ARRAYSZ             : 'DT_INIT_ARRAYSZ',
            Dynamic.DT_FINI_ARRAYSZ             : 'DT_FINI_ARRAYSZ',
            Dynamic.DT_RUNPATH                  : 'DT_RUN_PATH',
            Dynamic.DT_FLAGS                    : 'DT_FLAGS',
            Dynamic.DT_ENCODING                 : 'DT_ENCODING',
            Dynamic.DT_PREINIT_ARRAY            : 'DT_PREINIT_ARRAY',
            Dynamic.DT_PREINIT_ARRAYSZ          : 'DT_PREINIT_ARRAYSZ',
            Dynamic.DT_SCE_IDTABENTSZ           : 'DT_SCE_IDTABENTSZ',
            Dynamic.DT_SCE_FINGERPRINT          : 'DT_SCE_FINGERPRINT',
            Dynamic.DT_SCE_ORIGINAL_FILENAME    : 'DT_SCE_ORIGINAL_FILENAME',
            Dynamic.DT_SCE_MODULE_INFO          : 'DT_SCE_MODULE_INFO',
            Dynamic.DT_SCE_NEEDED_MODULE        : 'DT_SCE_NEEDED_MODULE',
            Dynamic.DT_SCE_MODULE_ATTR          : 'DT_SCE_MODULE_ATTR',
            Dynamic.DT_SCE_EXPORT_LIB           : 'DT_SCE_EXPORT_LIB',
            Dynamic.DT_SCE_IMPORT_LIB           : 'DT_SCE_IMPORT_LIB',
            Dynamic.DT_SCE_EXPORT_LIB_ATTR      : 'DT_SCE_EXPORT_LIB_ATTR',
            Dynamic.DT_SCE_IMPORT_LIB_ATTR      : 'DT_SCE_IMPORT_LIB_ATTR',
            Dynamic.DT_SCE_STUB_MODULE_NAME     : 'DT_SCE_STUB_MODULE_NAME',
            Dynamic.DT_SCE_STUB_MODULE_VERSION  : 'DT_SCE_STUB_MODULE_VERSION',
            Dynamic.DT_SCE_STUB_LIBRARY_NAME    : 'DT_SCE_STUB_LIBRARY_NAME',
            Dynamic.DT_SCE_STUB_LIBRARY_VERSION : 'DT_SCE_STUB_LIBRARY_VERSION',
            Dynamic.DT_SCE_HASH                 : 'DT_SCE_HASH',
            Dynamic.DT_SCE_PLTGOT               : 'DT_SCE_PLTGOT',
            Dynamic.DT_SCE_JMPREL               : 'DT_SCE_JMPREL',
            Dynamic.DT_SCE_PLTREL               : 'DT_SCE_PLTREL',
            Dynamic.DT_SCE_PLTRELSZ             : 'DT_SCE_PLTRELSZ',
            Dynamic.DT_SCE_RELA                 : 'DT_SCE_RELA',
            Dynamic.DT_SCE_RELASZ               : 'DT_SCE_RELASZ',
            Dynamic.DT_SCE_RELAENT              : 'DT_SCE_RELAENT',
            Dynamic.DT_SCE_STRTAB               : 'DT_SCE_STRTAB',
            Dynamic.DT_SCE_STRSZ                : 'DT_SCE_STRSZ',
            Dynamic.DT_SCE_SYMTAB               : 'DT_SCE_SYMTAB',
            Dynamic.DT_SCE_SYMENT               : 'DT_SCE_SYMENT',
            Dynamic.DT_SCE_HASHSZ               : 'DT_SCE_HASHSZ',
            Dynamic.DT_SCE_SYMTABSZ             : 'DT_SCE_SYMTABSZ',
            Dynamic.DT_SCE_HIOS                 : 'DT_SCE_HIOS',
            Dynamic.DT_GNU_HASH                 : 'DT_GNU_HASH',
            Dynamic.DT_VERSYM                   : 'DT_VERSYM',
            Dynamic.DT_RELACOUNT                : 'DT_RELACOUNT',
            Dynamic.DT_RELCOUNT                 : 'DT_RELCOUNT',
            Dynamic.DT_FLAGS_1                  : 'DT_FLAGS_1',
            Dynamic.DT_VERDEF                   : 'DT_VERDEF',
            Dynamic.DT_VERDEFNUM                : 'DT_VERDEFNUM',
        }.get(self.TAG, 'Missing Dynamic Tag!!!')
    
    def lib_attribute(self):
    
        return {
            0x1  : 'AUTO_EXPORT',
            0x2  : 'WEAK_EXPORT',
            0x8  : 'LOOSE_IMPORT',
            0x9  : 'AUTO_EXPORT|LOOSE_IMPORT',
            0xA  : 'WEAK_EXPORT|LOOSE_IMPORT',
        }.get(self.INDEX, 'Missing Library Attribute!!!')
    
    def mod_attribute(self):
    
        return {
            0x0  : 'NONE',
            0x1  : 'SCE_CANT_STOP',
            0x2  : 'SCE_EXCLUSIVE_LOAD',
            0x4  : 'SCE_EXCLUSIVE_START',
            0x8  : 'SCE_CAN_RESTART',
            0x10 : 'SCE_CAN_RELOCATE',
            0x20 : 'SCE_CANT_SHARE',
        }.get(self.INDEX, 'Missing Module Attribute!!!')
    
    def comment(self, address, stubs, modules, libraries):
    
        if self.TAG in [Dynamic.DT_NEEDED, Dynamic.DT_SONAME]:
            return '%s | %s' % (self.tag(), str(stubs[self.VALUE]))
        elif self.TAG == Dynamic.DT_SCE_HASH:
            address += Dynamic.HASHTAB
            idc.add_entry(address, address, '.hash', False)
            return '%s | %#x' % (self.tag(), address)
        elif self.TAG == Dynamic.DT_SCE_STRTAB:
            address += Dynamic.STRTAB
            idc.add_entry(address, address, '.dynstr', False)
            return '%s | %#x' % (self.tag(), address)
        elif self.TAG == Dynamic.DT_SCE_SYMTAB:
            address += Dynamic.SYMTAB
            idc.add_entry(address, address, '.dynsym', False)
            return '%s | %#x' % (self.tag(), address)
        elif self.TAG == Dynamic.DT_SCE_JMPREL:
            return '%s | %#x' % (self.tag(), address + Dynamic.JMPTAB)
        elif self.TAG == Dynamic.DT_SCE_RELA:
            return '%s | %#x' % (self.tag(), address + Dynamic.RELATAB)
        elif self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_IMPORT_LIB,
                          Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB,
                          Dynamic.DT_SCE_EXPORT_LIB_ATTR, Dynamic.DT_SCE_MODULE_INFO,
                          Dynamic.DT_SCE_MODULE_ATTR, Dynamic.DT_SCE_FINGERPRINT,
                          Dynamic.DT_SCE_ORIGINAL_FILENAME]:
            self.ID             = self.VALUE >> 48
            self.VERSION_MINOR  = (self.VALUE >> 40) & 0xF
            self.VERSION_MAJOR  = (self.VALUE >> 32) & 0xF
            self.INDEX          = self.VALUE & 0xFFF
            
            if self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_MODULE_INFO]:
                return '%s | MID:%#x Version:%i.%i Name:%s' % \
                       (self.tag(), self.ID, self.VERSION_MAJOR, self.VERSION_MINOR, str(modules[self.INDEX]))
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB, Dynamic.DT_SCE_EXPORT_LIB]:
                return '%s | LID:%#x Version:%i Name:%s' % \
                       (self.tag(), self.ID, self.VERSION_MAJOR, str(libraries[self.INDEX]))
            elif self.TAG == Dynamic.DT_SCE_MODULE_ATTR:
                return '%s | %s' % (self.tag(), self.mod_attribute())
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB_ATTR]:
                return '%s | LID:%#x Attributes:%s' % \
                       (self.tag(), self.ID, self.lib_attribute())
            elif self.TAG == Dynamic.DT_SCE_FINGERPRINT:
                return '%s | %s' % (self.tag(), Dynamic.FINGERPRINT)
            elif self.TAG == Dynamic.DT_SCE_ORIGINAL_FILENAME:
                return '%s | %s' % (self.tag(), str(stubs[self.VALUE]))
        
        return '%s | %#x' % (self.tag(), self.VALUE)
    
    def process(self, stubs, modules, libraries):
    
        if self.TAG == Dynamic.DT_INIT:
            Dynamic.INIT = self.VALUE
            idc.add_entry(Dynamic.INIT, Dynamic.INIT, '.init', True)
        elif self.TAG == Dynamic.DT_FINI:
            Dynamic.FINI = self.VALUE
            idc.add_entry(Dynamic.FINI, Dynamic.FINI, '.fini', True)
        elif self.TAG in [Dynamic.DT_NEEDED, Dynamic.DT_SONAME]:
            stubs[self.VALUE] = 0
        elif self.TAG == Dynamic.DT_SCE_STRTAB:
            Dynamic.STRTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_STRSZ:
            Dynamic.STRTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_SYMTAB:
            Dynamic.SYMTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_SYMTABSZ:
            Dynamic.SYMTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_JMPREL:
            Dynamic.JMPTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_PLTRELSZ:
            Dynamic.JMPTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_PLTREL:
            if self.VALUE == 0x7:
                return '%s | %#x | DT_RELA' % (self.tag(), self.VALUE)
        elif self.TAG == Dynamic.DT_SCE_RELA:
            Dynamic.RELATAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_RELASZ:
            Dynamic.RELATABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_HASH:
            Dynamic.HASHTAB = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_HASHSZ:
            Dynamic.HASHTABSZ = self.VALUE
        elif self.TAG == Dynamic.DT_SCE_PLTGOT:
            Dynamic.GOT = self.VALUE
            idc.add_entry(Dynamic.GOT, Dynamic.GOT, '.got.plt', False)
        elif self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_IMPORT_LIB,
                          Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB,
                          Dynamic.DT_SCE_EXPORT_LIB_ATTR, Dynamic.DT_SCE_MODULE_INFO,
                          Dynamic.DT_SCE_MODULE_ATTR, Dynamic.DT_SCE_FINGERPRINT,
                          Dynamic.DT_SCE_ORIGINAL_FILENAME]:
            self.ID             = self.VALUE >> 48
            self.VERSION_MINOR  = (self.VALUE >> 40) & 0xF
            self.VERSION_MAJOR  = (self.VALUE >> 32) & 0xF
            self.INDEX          = self.VALUE & 0xFFF
            
            if self.TAG in [Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_MODULE_INFO]:
                modules[self.INDEX] = 0
                return '%s | MID:%#x Version:%i.%i | %#x' % \
                       (self.tag(), self.ID, self.VERSION_MAJOR, self.VERSION_MINOR, self.INDEX)
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB, Dynamic.DT_SCE_EXPORT_LIB]:
                libraries[self.INDEX] = self.ID
                return '%s | LID:%#x Version:%i | %#x' % \
                       (self.tag(), self.ID, self.VERSION_MAJOR, self.INDEX)
            elif self.TAG == Dynamic.DT_SCE_MODULE_ATTR:
                return '%s | %s' % (self.tag(), self.mod_attribute())
            elif self.TAG in [Dynamic.DT_SCE_IMPORT_LIB_ATTR, Dynamic.DT_SCE_EXPORT_LIB_ATTR]:
                return '%s | LID:%#x Attributes:%s' % \
                       (self.tag(), self.ID, self.lib_attribute())
            elif self.TAG == Dynamic.DT_SCE_FINGERPRINT:
                Dynamic.FINGERPRINT = self.VALUE
            elif self.TAG == Dynamic.DT_SCE_ORIGINAL_FILENAME:
                stubs[self.INDEX] = 0
        
        return '%s | %#x' % (self.tag(), self.VALUE)
    

class Relocation:

    __slots__ = ('OFFSET', 'INDEX', 'INFO', 'ADDEND')
    
    # PS4 (X86_64) Relocation Codes (40)
    (R_X86_64_NONE, R_X86_64_64, R_X86_64_PC32, R_X86_64_GOT32,
    R_X86_64_PLT32, R_X86_64_COPY, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT,
    R_X86_64_RELATIVE, R_X86_64_GOTPCREL, R_X86_64_32, R_X86_64_32S,
    R_X86_64_16, R_X86_64_PC16, R_X86_64_8, R_X86_64_PC8, R_X86_64_DTPMOD64,
    R_X86_64_DTPOFF64, R_X86_64_TPOFF64, R_X86_64_TLSGD, R_X86_64_TLSLD,
    R_X86_64_DTPOFF32, R_X86_64_GOTTPOFF, R_X86_64_TPOFF32, R_X86_64_PC64,
    R_X86_64_GOTOFF64, R_X86_64_GOTPC32, R_X86_64_GOT64, R_X86_64_GOTPCREL64,
    R_X86_64_GOTPC64, R_X86_64_GOTPLT64, R_X86_64_PLTOFF64, R_X86_64_SIZE32,
    R_X86_64_SIZE64, R_X86_64_GOTPC32_TLSDESC, R_X86_64_TLSDESC_CALL, R_X86_64_TLSDESC,
    R_X86_64_IRELATIVE, R_X86_64_RELATIVE64) = range(0x27)
    R_X86_64_ORBIS_GOTPCREL_LOAD             = 0x28 
    
    def __init__(self, f):
    
        self.OFFSET = struct.unpack('<Q', f.read(8))[0]
        self.INFO   = struct.unpack('<Q', f.read(8))[0]
        self.ADDEND = struct.unpack('<Q', f.read(8))[0]
    
    def type(self):
    
        return {
            Relocation.R_X86_64_NONE                : 'R_X86_64_NONE',
            Relocation.R_X86_64_64                  : 'R_X86_64_64',
            Relocation.R_X86_64_PC32                : 'R_X86_64_PC32',
            Relocation.R_X86_64_GOT32               : 'R_X86_64_GOT32',
            Relocation.R_X86_64_PLT32               : 'R_X86_64_PLT32',
            Relocation.R_X86_64_COPY                : 'R_X86_64_COPY',
            Relocation.R_X86_64_GLOB_DAT            : 'R_X86_64_GLOB_DAT',
            Relocation.R_X86_64_JUMP_SLOT           : 'R_X86_64_JUMP_SLOT',
            Relocation.R_X86_64_RELATIVE            : 'R_X86_64_RELATIVE',
            Relocation.R_X86_64_GOTPCREL            : 'R_X86_64_GOTPCREL',
            Relocation.R_X86_64_32                  : 'R_X86_64_32',
            Relocation.R_X86_64_32S                 : 'R_X86_64_32S',
            Relocation.R_X86_64_16                  : 'R_X86_64_16',
            Relocation.R_X86_64_PC16                : 'R_X86_64_PC16',
            Relocation.R_X86_64_8                   : 'R_X86_64_8',
            Relocation.R_X86_64_PC8                 : 'R_X86_64_PC8',
            Relocation.R_X86_64_DTPMOD64            : 'R_X86_64_DTPMOD64',
            Relocation.R_X86_64_DTPOFF64            : 'R_X86_64_DTPOFF64',
            Relocation.R_X86_64_TPOFF64             : 'R_X86_64_TPOFF64',
            Relocation.R_X86_64_TLSGD               : 'R_X86_64_TLSGD',
            Relocation.R_X86_64_TLSLD               : 'R_X86_64_TLSLD',
            Relocation.R_X86_64_DTPOFF32            : 'R_X86_64_DTPOFF32',
            Relocation.R_X86_64_GOTTPOFF            : 'R_X86_64_GOTTPOFF',
            Relocation.R_X86_64_TPOFF32             : 'R_X86_64_TPOFF32',
            Relocation.R_X86_64_PC64                : 'R_X86_64_PC64',
            Relocation.R_X86_64_GOTOFF64            : 'R_X86_64_GOTOFF64',
            Relocation.R_X86_64_GOTPC32             : 'R_X86_64_GOTPC32',
            Relocation.R_X86_64_GOT64               : 'R_X86_64_GOT64',
            Relocation.R_X86_64_GOTPCREL64          : 'R_X86_64_GOTPCREL64',
            Relocation.R_X86_64_GOTPC64             : 'R_X86_64_GOTPC64',
            Relocation.R_X86_64_GOTPLT64            : 'R_X86_64_GOTPLT64',
            Relocation.R_X86_64_PLTOFF64            : 'R_X86_64_PLTOFF64',
            Relocation.R_X86_64_SIZE32              : 'R_X86_64_SIZE32',
            Relocation.R_X86_64_SIZE64              : 'R_X86_64_SIZE64',
            Relocation.R_X86_64_GOTPC32_TLSDESC     : 'R_X86_64_GOTPC32_TLSDESC',
            Relocation.R_X86_64_TLSDESC_CALL        : 'R_X86_64_TLSDESC_CALL',
            Relocation.R_X86_64_TLSDESC             : 'R_X86_64_TLSDESC',
            Relocation.R_X86_64_IRELATIVE           : 'R_X86_64_IRELATIVE',
            Relocation.R_X86_64_RELATIVE64          : 'R_X86_64_RELATIVE64',
            Relocation.R_X86_64_ORBIS_GOTPCREL_LOAD : 'R_X86_64_ORBIS_GOTPCREL_LOAD',
        }.get(self.INFO, 'Missing PS4 Relocation Type!!!')
    
    def process(self, nids, symbols):
    
        if self.INFO > Relocation.R_X86_64_ORBIS_GOTPCREL_LOAD:
            self.INDEX = self.INFO >> 32
            self.INFO &= 0xFF
            
            # Symbol Value + AddEnd (S + A)
            if self.type() == 'R_X86_64_64':
                self.INDEX += self.ADDEND
            
            if self.type() != 'R_X86_64_DTPMOD64':
                symbol = next(value for key, value in enumerate(symbols) if key + 2 == self.INDEX)[1]
        
        # String (Offset) == Base + AddEnd (B + A)
        if self.type() == 'R_X86_64_RELATIVE':
            idaapi.put_qword(self.OFFSET, self.ADDEND)
            idaapi.create_data(self.OFFSET, FF_QWORD, 0x8, BADNODE)
        
        # TLS Object
        elif self.type() in ['R_X86_64_DTPMOD64', 'R_X86_64_DTPOFF64']:
            idc.set_name(self.OFFSET, 'tls_access_struct', SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        # Object
        else:
            # Resolve the NID...
            try:
                idc.set_cmt(self.OFFSET, 'NID: ' + symbol, False)
            except:
                pass
            object = nids.get(symbol[:11], symbol)
            
            # Rename the Object...
            idc.set_name(self.OFFSET, object, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            idaapi.create_data(self.OFFSET, FF_QWORD, 0x8, BADNODE)
        
        return self.type()
    
    def resolve(self, alphabet, nids, symbols, libraries):
    
        if self.INFO > Relocation.R_X86_64_ORBIS_GOTPCREL_LOAD:
            self.INDEX = self.INFO >> 32
            self.INFO &= 0xFF
            symbol = next(value for key, value in enumerate(symbols) if key + 2 == self.INDEX)[1]
        
        # Library
        try:
            lid1 = alphabet[symbol[12:13]]
            
            # [base64]#
            if symbol[13:14] == '#':
                library = libraries[lid1]
            
            # [base64][base64]#
            elif symbol[14:15] == '#':
                lid2 = alphabet[symbol[13:14]]
                library = libraries[lid1 + lid2]
            
            else:
                raise
        
        # Not a NID
        except:
            library = ''
        
        # Function Name (Offset) == Symbol Value + AddEnd (S + A)
        # Library Name  (Offset) == Symbol Value (S)
        real = idc.get_qword(self.OFFSET)
        idc.add_func(real)
        
        # Hacky way to determine if this is the real function...
        real -= 0x6 if idc.print_insn_mnem(real) == 'push' else 0x0
        
        # Resolve the NID...
        try:
            idc.set_cmt(real, 'NID: ' + symbol, False)
        except:
            pass
        function = str(nids.get(symbol[:11], symbol))
        
        # Rename the Jump Function...
        idc.set_name(self.OFFSET, '__imp_' + function, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        # Rename the Real Function...
        idc.set_name(real, function, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        try:
            import_node = idaapi.netnode(str(library), 0, True)
            import_node.supset(ea2node(real), function)
            
            if hasattr(idaapi, 'import_module'):
                # Requires customized loader.i / ida_loader.py(d)
                idaapi.import_module(str(library), None, import_node.index(), None, 'linux')
            else:
                # Requires https://github.com/janisslsm/ida-ps4-helper
                idaapi.ext.import_module(str(library), '', import_node.index(), 'linux')
        except:
            pass
        
        return self.type()
    

class Symbol:

    __slots__ = ('NAME', 'INFO', 'OTHER', 'SHINDEX', 'VALUE', 'SIZE')
    
    # Symbol Information
    ST_LOCAL_NONE      = 0x0
    ST_LOCAL_OBJECT    = 0x1
    ST_LOCAL_FUNCTION  = 0x2
    ST_LOCAL_SECTION   = 0x3
    ST_LOCAL_FILE      = 0x4
    ST_LOCAL_COMMON    = 0x5
    ST_LOCAL_TLS       = 0x6
    ST_GLOBAL_NONE     = 0x10
    ST_GLOBAL_OBJECT   = 0x11
    ST_GLOBAL_FUNCTION = 0x12
    ST_GLOBAL_SECTION  = 0x13
    ST_GLOBAL_FILE     = 0x14
    ST_GLOBAL_COMMON   = 0x15
    ST_GLOBAL_TLS      = 0x16
    ST_WEAK_NONE       = 0x20
    ST_WEAK_OBJECT     = 0x21
    ST_WEAK_FUNCTION   = 0x22
    ST_WEAK_SECTION    = 0x23
    ST_WEAK_FILE       = 0x24
    ST_WEAK_COMMON     = 0x25
    ST_WEAK_TLS        = 0x26
    
    def __init__(self, f):
    
        self.NAME      = struct.unpack('<I', f.read(4))[0]
        self.INFO      = struct.unpack('<B', f.read(1))[0]
        self.OTHER     = struct.unpack('<B', f.read(1))[0]
        self.SHINDEX   = struct.unpack('<H', f.read(2))[0]
        self.VALUE     = struct.unpack('<Q', f.read(8))[0]
        self.SIZE      = struct.unpack('<Q', f.read(8))[0]
    
    def info(self):
    
        return {
            Symbol.ST_LOCAL_NONE      : 'Local : None',
            Symbol.ST_LOCAL_OBJECT    : 'Local : Object',
            Symbol.ST_LOCAL_FUNCTION  : 'Local : Function',
            Symbol.ST_LOCAL_SECTION   : 'Local : Section',
            Symbol.ST_LOCAL_FILE      : 'Local : File',
            Symbol.ST_LOCAL_COMMON    : 'Local : Common',
            Symbol.ST_LOCAL_TLS       : 'Local : TLS',
            Symbol.ST_GLOBAL_NONE     : 'Global : None',
            Symbol.ST_GLOBAL_OBJECT   : 'Global : Object',
            Symbol.ST_GLOBAL_FUNCTION : 'Global : Function',
            Symbol.ST_GLOBAL_SECTION  : 'Global : Section',
            Symbol.ST_GLOBAL_FILE     : 'Global : File',
            Symbol.ST_GLOBAL_COMMON   : 'Global : Common',
            Symbol.ST_GLOBAL_TLS      : 'Global : TLS',
            Symbol.ST_WEAK_NONE       : 'Weak : None',
            Symbol.ST_WEAK_OBJECT     : 'Weak : Object',
            Symbol.ST_WEAK_FUNCTION   : 'Weak : Function',
            Symbol.ST_WEAK_SECTION    : 'Weak : Section',
            Symbol.ST_WEAK_FILE       : 'Weak : File',
            Symbol.ST_WEAK_COMMON     : 'Weak : Common',
            Symbol.ST_WEAK_TLS        : 'Weak : TLS',
        }.get(self.INFO, 'Missing Symbol Information!!!')
    
    def process(self, symbols):
    
        if self.NAME != 0:
            symbols[self.NAME] = 0
        
        return self.info()
    
    def resolve(self, address, nids, symbol):
    
        # Resolve the NID...
        try:
            idc.set_cmt(self.VALUE, 'NID: ' + symbol, False)
        except:
            pass
        function = nids.get(symbol[:11], symbol)
        
        #print('Function: %s | number: %s' % (function, idaapi.get_func_num(self.VALUE)))
        if idaapi.get_func_num(self.VALUE) > 0:
            idc.del_func(self.VALUE)
        
        if self.VALUE > 0:
            idc.add_func(self.VALUE)
            idc.add_entry(self.VALUE, self.VALUE, function, True)
            idc.set_name(self.VALUE, function, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            idc.set_cmt(address, '%s | %s' % (function, self.info()), False)
        
    

# PROGRAM START

# Open File Dialog...
def accept_file(f, filename):

    ps4 = Binary(f)
    
    # No Kernels
    if ps4.E_MACHINE == Binary.EM_X86_64 and ps4.E_START_ADDR < 0xFFFFFFFF82200000:
        return { 'format': 'PS4 - ' + ps4.type(),
                 'options': ACCEPT_FIRST }
    return 0

# Since IDA cannot create a compatibility layer to save its life...
def find_binary(address, end, search, format, flags):
    
    # Is this really so hard Ilfak?
    # Not only do you break it between the beta and the release candidate... 
    # You then have the audacity to write in your release notes that you added find_binary, but it is nowhere to be seen
    # Feel free to take this version and modify it though to fit all edge cases, and in the spirit of your latest release, for free!
    if idaapi.IDA_SDK_VERSION > 760:
        binpat = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binpat, address, search, format)
        
        # 9.0 RC1
        try:
            address, _ = idaapi.bin_search(address, end, binpat, flags)
        # 9.0 Beta
        except:
            address, _ = idaapi.bin_search3(address, end, binpat, flags)
    else:
        address = idaapi.find_binary(address, end, search, format, flags)
    
    return address

# Load NID Library...
def load_nids(location, nids = {}):

    try:
        with open(location) as database:
            nids = dict(row for row in csv.reader(database, delimiter=' '))
    
    except IOError:
        retry = idaapi.ask_file(0, 'aerolib.csv|*.csv|All files (*.*)|*.*', 'Please gimme your aerolib.csv file')
        
        if retry != None:
            try:
                with open(retry) as database:
                    nids = dict(row for row in csv.reader(database, delimiter=' '))
                
                shutil.copy2(retry, location)
                
            except:
                print('Ok, no NIDs for you!')
        else:
            print('Ok, no NIDs for you!')
    
    return nids

# Pablo's Scripts
def pablo(mode, address, end, search):

    while address < end:
        address = find_binary(address, end, search, 0x10, SEARCH_DOWN)
        
        if address > idaapi.get_segm_by_name('CODE').end_ea:
            offset = address - 0x3
            
            if idaapi.is_unknown(idaapi.get_flags(offset)):
                if idaapi.get_qword(offset) <= end:
                    idaapi.create_data(offset, FF_QWORD, 0x8, BADNODE)
            
            address = offset + 0x4
        
        else:
            address += mode
            idaapi.del_items(address, 0)
            idaapi.create_insn(address)
            idaapi.add_func(address, BADADDR)
            address += 0x1

# Load Input Binary...
def load_file(f, neflags, format):

    print('# PS4 Module Loader')
    ps4 = Binary(f)
    
    # PS4 Processor, Compiler, Library
    bitness = ps4.procomp('metapc', CM_N64 | CM_M_NN | CM_CC_FASTCALL, 'ps4_errno_700')
    
    # Load Aerolib...
    nids = load_nids(idc.idadir() + '/loaders/aerolib.csv')
    
    # Segment Loading...
    for segm in ps4.E_SEGMENTS:
    
        # Process Loadable Segments...
        if segm.name() in ['CODE', 'DATA', 'SCE_RELRO', 'DYNAMIC', 'GNU_EH_FRAME', 'SCE_DYNLIBDATA']:
        
            address = segm.MEM_ADDR if segm.name() not in ['DYNAMIC', 'SCE_DYNLIBDATA'] else segm.OFFSET + 0x1000000
            size    = segm.MEM_SIZE if segm.name() not in ['DYNAMIC', 'SCE_DYNLIBDATA'] else segm.FILE_SIZE
            
            print('# Processing %s Segment...' % segm.name())
            f.file2base(segm.OFFSET, address, address + segm.FILE_SIZE, FILEREG_PATCHABLE)
            
            if segm.name() not in ['DYNAMIC', 'GNU_EH_FRAME']:
                
                idaapi.add_segm(0, address, address + size, segm.name(), segm.type(), ADDSEG_NOTRUNC | ADDSEG_FILLGAP)
                
                # Processor Specific Segment Details
                idc.set_segm_addressing(address, bitness)
                idc.set_segm_alignment(address, segm.alignment())
                idc.set_segm_attr(address, SEGATTR_PERM, segm.flags())
            
            # Process Dynamic Segment....
            elif segm.name() == 'DYNAMIC':
            
                stubs = {}
                modules = {}
                libraries = {}
                f.seek(segm.OFFSET)
                
                offset = segm.OFFSET
                dynamic = address
                dynamicsize = size
                
                for entry in range(int(dynamicsize / 0x10)):
                    idc.set_cmt(address + (entry * 0x10), Dynamic(f).process(stubs, modules, libraries), False)
            
            '''
            # Process Exception Handling Segment...
            elif segm.name() == 'GNU_EH_FRAME':
                
                # Exception Handling Frame Header Structure
                members = [('version', 'Version', 0x1),
                           ('eh_frame_ptr_enc', 'Encoding of Exception Handling Frame Pointer', 0x1),
                           ('fde_count_enc', 'Encoding of Frame Description Entry Count', 0x1),
                           ('table_enc', 'Encoding of Table Entries', 0x1)]
                struct = segm.struct('EHFrame', members)
                
                idaapi.create_struct(address, 0x4, struct)
                
                # Exception Handling Structure
                members = [('exception', 'value', 0x8)]
                struct = segm.struct('Exception', members)
                
                for entry in range(int(size / 0x8)):
                    idaapi.create_struct(address + (entry * 0x8), 0x8, struct)
            '''
        
        # Process SCE 'Special' Shared Object Segment...
        if segm.name() == 'SCE_DYNLIBDATA':
        
            # SCE Fingerprint
            idc.make_array(address, 0x14)
            idc.set_name(address, 'SCE_FINGERPRINT', SN_NOCHECK | SN_NOWARN | SN_FORCE)
            #idc.set_cmt(address, ' '.join(x.encode('hex') for x in idc.get_bytes(address, 0x14)).upper(), False)
            
            # Dynamic Symbol Table
            try:
                # --------------------------------------------------------------------------------------------------------
                # Dynamic Symbol Entry Structure
                members = [('name', 'Name (String Index)', 0x4),
                           ('info', 'Info (Binding : Type)', 0x1),
                           ('other', 'Other', 0x1),
                           ('shtndx', 'Section Index', 0x2),
                           ('value', 'Value', 0x8),
                           ('size', 'Size', 0x8)]
                struct = segm.struct('Symbol', members)
                
                # Dynamic Symbol Table
                location = address + Dynamic.SYMTAB
                f.seek(segm.OFFSET + Dynamic.SYMTAB)
                symbols = {}
                
                for entry in range(int(Dynamic.SYMTABSZ / 0x18)):
                    idaapi.create_struct(location + (entry * 0x18), 0x18, struct)
                    idc.set_cmt(location + (entry * 0x18), Symbol(f).process(symbols), False)
                
            except:
                pass
            
            # Dynamic String Table
            try:
                # --------------------------------------------------------------------------------------------------------
                # Dynamic String Table
                location = address + Dynamic.STRTAB
                f.seek(segm.OFFSET + Dynamic.STRTAB)
                
                # Stubs
                for key in stubs:
                    idc.create_strlit(location + key, BADADDR)
                    stubs[key] = idc.get_strlit_contents(location + key, BADADDR).decode()
                    idc.set_cmt(location + key, 'Stub', False)
                
                #print('Stubs: %s' % stubs)
                
                # Modules
                for key in modules:
                    idc.create_strlit(location + key, BADADDR)
                    modules[key] = idc.get_strlit_contents(location + key, BADADDR).decode()
                    idc.set_cmt(location + key, 'Module', False)
                
                #print('Modules: %s' % modules)
                
                # Libraries and LIDs
                lids = {}
                for key, value in libraries.items():
                    idc.create_strlit(location + key, BADADDR)
                    lids[value] = idc.get_strlit_contents(location + key, BADADDR).decode()
                    libraries[key] = idc.get_strlit_contents(location + key, BADADDR).decode()
                    idc.set_cmt(location + key, 'Library', False)
                
                #print('LIDs: %s' % lids)
                
                # Symbols
                for key in symbols:
                    idc.create_strlit(location + key, BADADDR)
                    symbols[key] = idc.get_strlit_contents(location + key, BADADDR).decode()
                    idc.set_cmt(location + key, 'Symbol', False)
                
                #print('Symbols: %s' % symbols)
                
            except:
                pass
            
            # Resolve Export Symbols
            try:
                symbols = sorted(symbols.items())
                location = address + Dynamic.SYMTAB + 0x30
                f.seek(segm.OFFSET + Dynamic.SYMTAB + 0x30)
                
                for entry in range(int((Dynamic.SYMTABSZ - 0x30) / 0x18)):
                    Symbol(f).resolve(location + (entry * 0x18), nids, symbols[entry][1])
                
            except:
                pass
            
            # Jump Table
            try:
                # --------------------------------------------------------------------------------------------------------
                # Jump Entry Structure
                members = [('offset', 'Offset (String Index)', 0x8),
                           ('info', 'Info (Symbol Index : Relocation Code)', 0x8),
                           ('addend', 'AddEnd', 0x8)]
                struct = segm.struct('Jump', members)
                
                # PS4 Base64 Alphabet
                base64 = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-')
                alphabet = { character:index for index, character in enumerate(base64) }
                #print('Base64 Table: %s' % alphabet)
                
                # Jump Table
                location = address + Dynamic.JMPTAB
                f.seek(segm.OFFSET + Dynamic.JMPTAB)
                
                for entry in range(int(Dynamic.JMPTABSZ / 0x18)):
                    idaapi.create_struct(location + (entry * 0x18), 0x18, struct)
                    idc.set_cmt(location + (entry * 0x18), Relocation(f).resolve(alphabet, nids, symbols, lids), False)
                
            except:
                pass
            
            # Relocation Table
            try:
                # --------------------------------------------------------------------------------------------------------
                # Relocation Entry Structure (with specific addends)
                members = [('offset', 'Offset (String Index)', 0x8),
                           ('info', 'Info (Symbol Index : Relocation Code)', 0x8),
                           ('addend', 'AddEnd', 0x8)]
                struct = segm.struct('Relocation', members)
                
                # Relocation Table (with specific addends)
                location = address + Dynamic.RELATAB
                f.seek(segm.OFFSET + Dynamic.RELATAB)
                
                for entry in range(int(Dynamic.RELATABSZ / 0x18)):
                    idaapi.create_struct(location + (entry * 0x18), 0x18, struct)
                    idc.set_cmt(location + (entry * 0x18), Relocation(f).process(nids, symbols), False)
                
            except:
                pass
            
            # Hash Table
            try:
                # --------------------------------------------------------------------------------------------------------
                # Hash Entry Structure
                members = [('bucket', 'Bucket', 0x2),
                           ('chain', 'Chain', 0x2),
                           ('buckets', 'Buckets', 0x2),
                           ('chains', 'Chains', 0x2)]
                struct = segm.struct('Hash', members)
                
                # Hash Table
                location = address + Dynamic.HASHTAB
                f.seek(segm.OFFSET + Dynamic.HASHTAB)
                
                for entry in range(int(Dynamic.HASHTABSZ / 0x8)):
                    idaapi.create_struct(location + (entry * 0x8), 0x8, struct)
                
            except:
                pass
            
            # Dynamic Tag Table
            try:
                # --------------------------------------------------------------------------------------------------------
                # Dynamic Tag Entry Structure
                members = [('tag', 'Tag', 0x8),
                           ('value', 'Value', 0x8)]
                struct = segm.struct('Tag', members)
                
                f.seek(offset)
                
                for entry in range(int(dynamicsize / 0x10)):
                    idaapi.create_struct(dynamic + (entry * 0x10), 0x10, struct)
                    idc.set_cmt(dynamic + (entry * 0x10), Dynamic(f).comment(address, stubs, modules, libraries), False)
                
            except:
                pass
            
    
    code = idaapi.get_segm_by_name('CODE')
    
    # Start Function
    idc.add_entry(ps4.E_START_ADDR, ps4.E_START_ADDR, 'start', True)
    
    # Set No Return for __stack_chk_fail...
    try:
        function = idc.get_name_ea_simple('__stack_chk_fail')
        function = idaapi.get_func(function)
        function.flags |= FUNC_NORET
        idaapi.update_func(function)
    
    except:
        pass
    
    # --------------------------------------------------------------------------------------------------------
    # Pablo's Scripts
    try:
        print('# Processing Pablo\'s Push script...')
        
        # Script 1) Push it real good...
        # Default patterns set
        pablo(0, code.start_ea, 0x10, '55 48 89')
        pablo(2, code.start_ea, code.end_ea, '90 90 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'C3 90 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '66 90 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'C9 C3 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '0F 0B 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'EB ?? 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '5D C3 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '5B C3 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '90 90 55 41 ?? 41 ??')
        pablo(2, code.start_ea, code.end_ea, '66 90 48 81 EC ?? 00 00 00')
        pablo(2, code.start_ea, code.end_ea, '0F 0B 48 89 9D ?? ?? FF FF 49 89')
        pablo(2, code.start_ea, code.end_ea, '90 90 53 4C 8B 54 24 20')
        pablo(2, code.start_ea, code.end_ea, '90 90 55 41 56 53')
        pablo(2, code.start_ea, code.end_ea, '90 90 53 48 89')
        pablo(2, code.start_ea, code.end_ea, '90 90 41 ?? 41 ??')
        pablo(3, code.start_ea, code.end_ea, '0F 0B 90 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, 'EB ?? 90 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5F C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5C C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '31 C0 C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5D C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5E C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '66 66 90 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '0F 1F 00 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 ?? C3 53 48')
        pablo(3, code.start_ea, code.end_ea, '0F 1F 00 48 81 EC ?? 00 00 00')
        pablo(4, code.start_ea, code.end_ea, '0F 1F 40 00 55 48 ??')
        pablo(4, code.start_ea, code.end_ea, '0F 1F 40 00 48 81 EC ?? 00 00 00')
        pablo(5, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, 'E8 ?? ?? ?? ?? 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, '48 83 C4 ?? C3 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, '0F 1F 44 00 00 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, '0F 1F 44 00 00 48 81 EC ?? 00 00 00')
        pablo(6, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 55 48 ??')
        pablo(6, code.start_ea, code.end_ea, 'E8 ?? ?? ?? ?? 90 55 48 ??')
        pablo(6, code.start_ea, code.end_ea, '66 0F 1F 44 00 00 55 48 ??')
        pablo(7, code.start_ea, code.end_ea, '0F 1F 80 00 00 00 00 55 48 ??')
        pablo(8, code.start_ea, code.end_ea, '0F 1F 84 00 00 00 00 00 55 48 ??')
        pablo(8, code.start_ea, code.end_ea, 'C3 0F 1F 80 00 00 00 00 48')
        pablo(8, code.start_ea, code.end_ea, '0F 1F 84 00 00 00 00 00 53 48 83 EC')
        
        # Special cases patterns set
        pablo(13, code.start_ea, code.end_ea, 'C3 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(13, code.start_ea, code.end_ea, 'C3 90 90 90 90 90 90 90 90 90 90 90 90 55')
        pablo(17, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(19, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(19, code.start_ea, code.end_ea, 'E8 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(20, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(20, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')

    except:
        pass
    
    # --------------------------------------------------------------------------------------------------------
    # Chendo's Syscall Commenter
    try:
        print('# Processing Chendo\'s Syscall Commenter...')
        
        SYSCALLS = [
            'nosys',
            'exit',
            'fork',
            'read',
            'write',
            'open',
            'close',
            'wait4',
            'creat',
            'link',
            'unlink',
            'execv',
            'chdir',
            'fchdir',
            'mkd',
            'chmod',
            'chown',
            'obreak',
            'getfsstat',
            'lseek',
            'getpid',
            'mount',
            'unmount',
            'setuid',
            'getuid',
            'geteuid',
            'ptrace',
            'recvmsg',
            'sendmsg',
            'recvfrom',
            'accept',
            'getpeername',
            'getsockname',
            'access',
            'chflags',
            'fchflags',
            'sync',
            'kill',
            'stat',
            'getppid',
            'lstat',
            'dup',
            'pipe',
            'getegid',
            'profil',
            'ktrace',
            'sigaction',
            'getgid',
            'sigprocmask',
            'getlogin',
            'setlogin',
            'acct',
            'sigpending',
            'sigaltstack',
            'ioctl',
            'reboot',
            'revoke',
            'symlink',
            'readlink',
            'execve',
            'umask',
            'chroot',
            'fstat',
            'getkerninfo',
            'getpagesize',
            'msync',
            'vfork',
            'vread',
            'vwrite',
            'sbrk',
            'sstk',
            'mmap',
            'ovadvise',
            'munmap',
            'mprotect',
            'madvise',
            'vhangup',
            'vlimit',
            'mincore',
            'getgroups',
            'setgroups',
            'getpgrp',
            'setpgid',
            'setitimer',
            'wait',
            'swapon',
            'getitimer',
            'gethostname',
            'sethostname',
            'getdtablesize',
            'dup2',
            'getdopt',
            'fcntl',
            'select',
            'setdopt',
            'fsync',
            'setpriority',
            'socket',
            'connect',
            'accept',
            'getpriority',
            'send',
            'recv',
            'sigreturn',
            'bind',
            'setsockopt',
            'listen',
            'vtimes',
            'sigvec',
            'sigblock',
            'sigsetmask',
            'sigsuspend',
            'sigstack',
            'recvmsg',
            'sendmsg',
            'vtrace',
            'gettimeofday',
            'getrusage',
            'getsockopt',
            'resuba',
            'readv',
            'writev',
            'settimeofday',
            'fchown',
            'fchmod',
            'recvfrom',
            'setreuid',
            'setregid',
            'rename',
            'truncate',
            'ftruncate',
            'flock',
            'mkfifo',
            'sendto',
            'shutdown',
            'socketpair',
            'mkdir',
            'rmdir',
            'utimes',
            'sigreturn',
            'adjtime',
            'getpeername',
            'gethostid',
            'sethostid',
            'getrlimit',
            'setrlimit',
            'killpg',
            'setsid',
            'quotactl',
            'quota',
            'getsockname',
            'sem_lock',
            'sem_wakeup',
            'asyncdaemon',
            'nlm_syscall',
            'nfssvc',
            'getdirentries',
            'statfs',
            'fstatfs',
            '#159',
            'lgetfh',
            'getfh',
            'getdomainname',
            'setdomainname',
            'uname',
            'sysarch',
            'rtprio',
            '#167',
            '#168',
            'semsys',
            'msgsys',
            'shmsys',
            '#172',
            'pread',
            'pwrite',
            'setfib',
            'ntp_adjtime',
            'sfork',
            'getdescriptor',
            'setdescriptor',
            '#180',
            'setgid',
            'setegid',
            'seteuid',
            'lfs_bmapv',
            'lfs_markv',
            'lfs_segclean',
            'lfs_segwait',
            'stat',
            'fstat',
            'lstat',
            'pathconf',
            'fpathconf',
            '#193',
            'getrlimit',
            'setrlimit',
            'getdirentries',
            'mmap',
            'nosys',
            'lseek',
            'truncate',
            'ftruncate',
            'sysctl',
            'mlock',
            'munlock',
            'undelete',
            'futimes',
            'getpgid',
            'newreboot',
            'poll',
            '#210',
            '#211',
            '#212',
            '#213',
            '#214',
            '#215',
            '#216',
            '#217',
            '#218',
            '#219',
            'semctl',
            'semget',
            'semop',
            'semconfig',
            'msgctl',
            'msgget',
            'msgsnd',
            'msgrcv',
            'shmat',
            'shmctl',
            'shmdt',
            'shmget',
            'clock_gettime',
            'clock_settime',
            'clock_getres',
            'ktimer_create',
            'ktimer_delete',
            'ktimer_settime',
            'ktimer_gettime',
            'ktimer_getoverrun',
            'nasleep',
            'ffclock_getcounter',
            'ffclock_setestimate',
            'ffclock_getestimate',
            '#244',
            '#245',
            '#246',
            'clock_getcpuclockid2',
            'ntp_gettime',
            '#249',
            'minherit',
            'rfork',
            'openbsd_poll',
            'issetugid',
            'lchown',
            'aio_read',
            'aio_write',
            'lio_listio',
            '#258',
            '#259',
            '#260',
            '#261',
            '#262',
            '#263',
            '#264',
            '#265',
            '#266',
            '#267',
            '#268',
            '#269',
            '#270',
            '#271',
            'getdents',
            '#273',
            'lchmod',
            'lchown',
            'lutimes',
            'msync',
            'nstat',
            'nfstat',
            'nlstat',
            '#281',
            '#282',
            '#283',
            '#284',
            '#285',
            '#286',
            '#287',
            '#288',
            'preadv',
            'pwritev',
            '#291',
            '#292',
            '#293',
            '#294',
            '#295',
            '#296',
            'fhstatfs',
            'fhopen',
            'fhstat',
            'modnext',
            'modstat',
            'modfnext',
            'modfind',
            'kldload',
            'kldunload',
            'kldfind',
            'kldnext',
            'kldstat',
            'kldfirstmod',
            'getsid',
            'setresuid',
            'setresgid',
            'signasleep',
            'aio_return',
            'aio_suspend',
            'aio_cancel',
            'aio_error',
            'aio_read',
            'aio_write',
            'lio_listio',
            'yield',
            'thr_sleep',
            'thr_wakeup',
            'mlockall',
            'munlockall',
            'getcwd',
            'sched_setparam',
            'sched_getparam',
            'sched_setscheduler',
            'sched_getscheduler',
            'sched_yield',
            'sched_get_priority_max',
            'sched_get_priority_min',
            'sched_rr_get_interval',
            'utrace',
            'sendfile',
            'kldsym',
            'jail',
            'nnpfs_syscall',
            'sigprocmask',
            'sigsuspend',
            'sigaction',
            'sigpending',
            'sigreturn',
            'sigtimedwait',
            'sigwaitinfo',
            'acl_get_file',
            'acl_set_file',
            'acl_get_fd',
            'acl_set_fd',
            'acl_delete_file',
            'acl_delete_fd',
            'acl_aclcheck_file',
            'acl_aclcheck_fd',
            'extattrctl',
            'extattr_set_file',
            'extattr_get_file',
            'extattr_delete_file',
            'aio_waitcomplete',
            'getresuid',
            'getresgid',
            'kqueue',
            'kevent',
            'cap_get_proc',
            'cap_set_proc',
            'cap_get_fd',
            'cap_get_file',
            'cap_set_fd',
            'cap_set_file',
            '#370',
            'extattr_set_fd',
            'extattr_get_fd',
            'extattr_delete_fd',
            'setugid',
            'nfsclnt',
            'eaccess',
            'afs3_syscall',
            'nmount',
            'kse_exit',
            'kse_wakeup',
            'kse_create',
            'kse_thr_interrupt',
            'kse_release',
            'mac_get_proc',
            'mac_set_proc',
            'mac_get_fd',
            'mac_get_file',
            'mac_set_fd',
            'mac_set_file',
            'kenv',
            'lchflags',
            'uuidgen',
            'sendfile',
            'mac_syscall',
            'getfsstat',
            'statfs',
            'fstatfs',
            'fhstatfs',
            '#399',
            'ksem_close',
            'ksem_post',
            'ksem_wait',
            'ksem_trywait',
            'ksem_init',
            'ksem_open',
            'ksem_unlink',
            'ksem_getvalue',
            'ksem_destroy',
            'mac_get_pid',
            'mac_get_link',
            'mac_set_link',
            'extattr_set_link',
            'extattr_get_link',
            'extattr_delete_link',
            'mac_execve',
            'sigaction',
            'sigreturn',
            'xstat',
            'xfstat',
            'xlstat',
            'getcontext',
            'setcontext',
            'swapcontext',
            'swapoff',
            'acl_get_link',
            'acl_set_link',
            'acl_delete_link',
            'acl_aclcheck_link',
            'sigwait',
            'thr_create',
            'thr_exit',
            'thr_self',
            'thr_kill',
            '#434',
            '#435',
            'jail_attach',
            'extattr_list_fd',
            'extattr_list_file',
            'extattr_list_link',
            'kse_switchin',
            'ksem_timedwait',
            'thr_suspend',
            'thr_wake',
            'kldunloadf',
            'audit',
            'auditon',
            'getauid',
            'setauid',
            'getaudit',
            'setaudit',
            'getaudit_addr',
            'setaudit_addr',
            'auditctl',
            'umtx_op',
            'thr_new',
            'sigqueue',
            'kmq_open',
            'kmq_setattr',
            'kmq_timedreceive',
            'kmq_timedsend',
            'kmq_tify',
            'kmq_unlink',
            'abort2',
            'thr_set_name',
            'aio_fsync',
            'rtprio_thread',
            '#467',
            '#468',
            'getpath_fromfd',
            'getpath_fromaddr',
            'sctp_peeloff',
            'sctp_generic_sendmsg',
            'sctp_generic_sendmsg_iov',
            'sctp_generic_recvmsg',
            'pread',
            'pwrite',
            'mmap',
            'lseek',
            'truncate',
            'ftruncate',
            'thr_kill2',
            'shm_open',
            'shm_unlink',
            'cpuset',
            'cpuset_setid',
            'cpuset_getid',
            'cpuset_getaffinity',
            'cpuset_setaffinity',
            'faccessat',
            'fchmodat',
            'fchownat',
            'fexecve',
            'fstatat',
            'futimesat',
            'linkat',
            'mkdirat',
            'mkfifoat',
            'mkdat',
            'openat',
            'readlinkat',
            'renameat',
            'symlinkat',
            'unlinkat',
            'posix_openpt',
            'gssd_syscall',
            'jail_get',
            'jail_set',
            'jail_remove',
            'closefrom',
            'semctl',
            'msgctl',
            'shmctl',
            'lpathconf',
            'cap_new',
            'cap_rights_get',
            'cap_enter',
            'cap_getmode',
            'pdfork',
            'pdkill',
            'pdgetpid',
            'pdwait4',
            'pselect',
            'getloginclass',
            'setloginclass',
            'rctl_get_racct',
            'rctl_get_rules',
            'rctl_get_limits',
            'rctl_add_rule',
            'rctl_remove_rule',
            'posix_fallocate',
            'posix_fadvise',
            'regmgr_call',
            'jitshm_create',
            'jitshm_alias',
            'dl_get_list',
            'dl_get_info',
            'dl_notify_event',
            'evf_create',
            'evf_delete',
            'evf_open',
            'evf_close',
            'evf_wait',
            'evf_trywait',
            'evf_set',
            'evf_clear',
            'evf_cancel',
            'query_memory_protection',
            'batch_map',
            'osem_create',
            'osem_delete',
            'osem_open',
            'osem_close',
            'osem_wait',
            'osem_trywait',
            'osem_post',
            'osem_cancel',
            'namedobj_create',
            'namedobj_delete',
            'set_vm_container',
            'debug_init',
            'suspend_process',
            'resume_process',
            'opmc_enable',
            'opmc_disable',
            'opmc_set_ctl',
            'opmc_set_ctr',
            'opmc_get_ctr',
            'budget_create',
            'budget_delete',
            'budget_get',
            'budget_set',
            'virtual_query',
            'mdbg_call',
            'sblock_create',
            'sblock_delete',
            'sblock_enter',
            'sblock_exit',
            'sblock_xenter',
            'sblock_xexit',
            'eport_create',
            'eport_delete',
            'eport_trigger',
            'eport_open',
            'eport_close',
            'is_in_sandbox',
            'dmem_container',
            'get_authinfo',
            'mname',
            'dynlib_dlopen',
            'dynlib_dlclose',
            'dynlib_dlsym',
            'dynlib_get_list',
            'dynlib_get_info',
            'dynlib_load_prx',
            'dynlib_unload_prx',
            'dynlib_do_copy_relocations',
            'dynlib_prepare_dlclose',
            'dynlib_get_proc_param',
            'dynlib_process_needed_and_relocate',
            'sandbox_path',
            'mdbg_service',
            'randomized_path',
            'rdup',
            'dl_get_metadata',
            'workaround8849',
            'is_development_mode',
            'get_self_auth_info',
            'dynlib_get_info_ex',
            'budget_getid',
            'budget_get_ptype',
            'get_paging_stats_of_all_threads',
            'get_proc_type_info',
            'get_resident_count',
            'prepare_to_suspend_process',
            'get_resident_fmem_count',
            'thr_get_name',
            'set_gpo',
            'get_paging_stats_of_all_objects',
            'test_debug_rwmem',
            'free_stack',
            'suspend_system',
            'ipmimgr_call',
            'get_gpo',
            'get_vm_map_timestamp',
            'opmc_set_hw',
            'opmc_get_hw',
            'get_cpu_usage_all',
            'mmap_dmem',
            'physhm_open',
            'physhm_unlink',
            'resume_internal_hdd',
            'thr_suspend_ucontext',
            'thr_resume_ucontext',
            'thr_get_ucontext',
            'thr_set_ucontext',
            'set_timezone_info',
            'set_phys_fmem_limit',
            'utc_to_localtime',
            'localtime_to_utc',
            'set_uevt',
            'get_cpu_usage_proc',
            'get_map_statistics',
            'set_chicken_switches',
            '#644',
            '#645',
            'get_kernel_mem_statistics',
            'get_sdk_compiled_version',
            'app_state_change',
            'dynlib_get_obj_member',
            'budget_get_ptype_of_budget',
            'prepare_to_resume_process',
            'process_terminate',
            'blockpool_open',
            'blockpool_map',
            'blockpool_unmap',
            'dynlib_get_info_for_libdbg',
            'blockpool_batch',
            'fdatasync',
            'dynlib_get_list2',
            'dynlib_get_info2',
            'aio_submit',
            'aio_multi_delete',
            'aio_multi_wait',
            'aio_multi_poll',
            'aio_get_data',
            'aio_multi_cancel',
            'get_bio_usage_all',
            'aio_create',
            'aio_submit_cmd',
            'aio_init',
            'get_page_table_stats',
            'dynlib_get_list_for_libdbg',
            'blockpool_move',
            'virtual_query_all',
            'reserve_2mb_page',
            'cpumode_yield',
            'get_phys_page_size'
        ]
        
        address = code.start_ea
        end     = code.end_ea
        
        while address < end:
            address = find_binary(address, end, '00 00 49 89 CA 0F 05', 0x10, SEARCH_DOWN)
            number = address - 0x2
            
            if address < end:
                number = idaapi.get_wide_word(number)
                idc.set_cmt(address + 0x5, 'sys_' + SYSCALLS[number], False)
                address += 0x8
            
    except:
        pass
    
    # --------------------------------------------------------------------------------------------------------
    # Error Code Enumerator
    try:
        print('# Processing Error Codes...')
        
        idc.import_type(-1, 'PS4_ERROR_CODES')
        
        member = idaapi.get_enum_member_by_name('SCE_KERNEL_ERROR_EPERM')
        enum   = idaapi.get_enum_member_enum(member)
        
        address = code.start_ea
        
        while True:
            address = idaapi.find_text(address, 0, 0, '80[0-9a-fA-F]{6}h', SEARCH_DOWN | SEARCH_NEXT | SEARCH_REGEX)
            if address == BADADDR: break
            
            # 0x80 is always at the end
            offset = idaapi.get_item_size(address) - 0x4
            errno = idaapi.get_dword(address + offset)
            
            if idaapi.get_enum_member(enum, errno, -1, 0) != BADADDR:
                idaapi.op_enum(address, 1, enum, 0)
            
            address = idaapi.next_head(address, BADADDR)
    
    except:
        pass
    
    print('# Done!')
    return 1

# PROGRAM END
