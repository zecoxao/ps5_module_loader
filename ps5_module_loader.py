#!/usr/bin/env python
'''

PS5 Module Loader

Derived from the PS4 Module Loader by SocraticBliss (R), retargeted at
PlayStation(R) 5 modules, whose dynamic layout differs substantially:

  * There is no PT_SCE_DYNLIBDATA blob.  The dynamic symbol table, string
    table, hash table and both relocation tables live at ordinary *virtual*
    addresses inside a regular (permission-less) PT_LOAD segment.
  * The standard DT_SYMTAB / DT_STRTAB / DT_RELA / DT_JMPREL / DT_HASH /
    DT_PLTGOT tags are used, with DT_SCE_SYMTABSZ / DT_SCE_HASHSZ supplying
    the two sizes ELF has no standard tag for.
  * The module / library tags were renumbered into the 0x6100004x range and
    the packed value changed shape:
        [63:48] = id   [47:40] = major   [39:32] = minor   [31:0] = name
    (a full 32-bit string table offset, not the PS4 12-bit index).
  * PT_SCE_RELRO was replaced by the generic PT_GNU_RELRO.

Credit for the original PS4 loader and its heuristics goes to SocraticBliss,
aerosoul, balika011, Znullptr, Pablo (kozarovv), ChendoChap, xyz, CelesteBlue,
kiwidogg, motoharu, noname120, flatz and Team Reswitched.

NOTE ON THE HASH CHARACTER
    Not one string literal in this file contains a literal U+0023.  Sony's
    symbol suffix and this loader's own log prefix both need one, and a
    careless comment stripper run over the source will happily truncate any
    line from the first one it sees -- taking the NID regex and every banner
    with it.  HASH below is that character; build such strings from it.

ps5_module_loader.py: IDA loader for reading Sony PlayStation(R) 5 Module files

'''

from idaapi import *
from idc import *
import sys
import ctypes
import idaapi
import idc
import re
import shutil
import struct

HASH = chr(0x23)


def log(text):

    print(HASH + ' ' + text)


# --------------------------------------------------------------------------------------------------------
# Sony's base64 alphabet, shared by the NID hash and the library/module suffixes
SCE_BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-'
ALPHABET   = dict((character, index) for index, character in enumerate(SCE_BASE64))

# <11 char NID> HASH <library id> HASH <module id>, both ids 1 or 2 base64 digits
NID_RE = re.compile(r'^([A-Za-z0-9+\-]{11})%s([A-Za-z0-9+\-]{1,2})%s([A-Za-z0-9+\-]{1,2})$'
                    % (HASH, HASH))


def decode_id(digits):

    value = 0
    for character in digits:
        value = (value * 0x40) + ALPHABET[character]
    return value


def split_nid(symbol):

    ''' Returns (nid, library id, module id), or (symbol, None, None) if it is not a NID '''

    match = NID_RE.match(symbol)
    if match is None:
        return symbol, None, None
    return match.group(1), decode_id(match.group(2)), decode_id(match.group(3))


def get_custom_base_address(original_base):

    ''' Ask user for custom base address -- returns (use_custom, base_address) '''

    choice = idaapi.ask_yn(idaapi.ASKBTN_YES,
                          "Do you want to load this PS5 module at a custom base address?\n\n"
                          "Original base: 0x%X\n\n"
                          "YES = Choose custom base\n"
                          "NO = Use original addresses\n"
                          "CANCEL = Use default 0x400000" % original_base)

    if choice == idaapi.ASKBTN_NO:
        return False, 0

    elif choice == idaapi.ASKBTN_CANCEL:
        return True, 0x400000

    custom_base = idaapi.ask_addr(0x400000,
                                 "Enter custom base address:\n\n"
                                 "Common bases:\n"
                                 "- 0x400000 (typical Linux/ELF)\n"
                                 "- 0x10000000 (high memory)\n"
                                 "- 0x140000000 (very high)\n\n"
                                 "Base address:")

    if custom_base is None or custom_base == idaapi.BADADDR:
        return False, 0

    if custom_base & 0xFFF != 0:
        if idaapi.ask_yn(idaapi.ASKBTN_YES,
                       "Warning: Address 0x%X is not page-aligned.\n"
                       "This may cause issues.\n\n"
                       "Continue anyway?" % custom_base) != idaapi.ASKBTN_YES:
            return False, 0

    return True, custom_base


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

        self.E_MACHINE  = 0
        self.E_SEGMENTS = []
        self.E_SECTIONS = []

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
        if self.EI_MAGIC != b'\x7fELF' or self.E_MACHINE != Binary.EM_X86_64:
            return

        f.seek(self.E_PHT_OFFSET)

        # Elf Program Header Table
        self.E_SEGMENTS = [Segment(f) for entry in range(self.E_PHT_COUNT)]

        try:
            if self.E_SHT_OFFSET:
                f.seek(self.E_SHT_OFFSET)
                self.E_SECTIONS = [Section(f) for entry in range(self.E_SHT_COUNT)]
        except:
            self.E_SECTIONS = []

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

    def is_ps5(self):

        ''' A PS4 module carries its dynamic tables inside PT_SCE_DYNLIBDATA.
            A PS5 module has no such segment -- the tables are plain virtual
            addresses -- and always ships a PT_DYNAMIC. '''

        if not self.E_SEGMENTS:
            return False

        if any(segm.TYPE == Segment.PT_SCE_DYNLIBDATA for segm in self.E_SEGMENTS):
            return False

        if not any(segm.TYPE == Segment.PT_DYNAMIC for segm in self.E_SEGMENTS):
            return False

        # Either an SCE elf type, or an ordinary ET_DYN/ET_EXEC carrying SCE segments
        if Binary.ET_SCE_EXEC <= self.E_TYPE <= Binary.ET_SCE_DYNAMIC:
            return True

        return any(segm.TYPE in (Segment.PT_SCE_MODULEPARAM, Segment.PT_SCE_PROCPARAM,
                                 Segment.PT_SCE_COMMENT, Segment.PT_SCE_LIBVERSION)
                   for segm in self.E_SEGMENTS)

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
        try:
            if til:
                idc.add_default_til(til)
        except:
            pass

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
    PT_GNU_RELRO           = 0x6474E552
    PT_GNU_PROPERTY        = 0x6474E553
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

        return self.FLAGS & 0x7

    def name(self):

        ''' PS5 modules hold several PT_LOADs whose role is only visible in the
            permission bits -- and the table-bearing one carries no permissions
            at all.  load_file() uniquifies these names afterwards. '''

        if self.TYPE == Segment.PT_LOAD:
            return {
                SEGPERM_EXEC | SEGPERM_READ                : 'CODE',
                SEGPERM_EXEC | SEGPERM_READ | SEGPERM_WRITE: 'CODE',
                SEGPERM_EXEC                               : 'CODE',
                SEGPERM_READ                               : 'RODATA',
                SEGPERM_READ | SEGPERM_WRITE               : 'DATA',
                SEGPERM_WRITE                              : 'DATA',
                0x0                                        : 'DYNLIB_DATA',
            }.get(self.flags(), 'LOAD')

        return {
            Segment.PT_NULL            : 'NULL',
            Segment.PT_DYNAMIC         : 'DYNAMIC',
            Segment.PT_INTERP          : 'INTERP',
            Segment.PT_NOTE            : 'NOTE',
            Segment.PT_SHLIB           : 'SHLIB',
            Segment.PT_PHDR            : 'PHDR',
            Segment.PT_TLS             : 'TLS',
            Segment.PT_SCE_DYNLIBDATA  : 'SCE_DYNLIBDATA',
            Segment.PT_SCE_PROCPARAM   : 'SCE_PROCPARAM',
            Segment.PT_SCE_MODULEPARAM : 'SCE_MODULEPARAM',
            Segment.PT_SCE_RELRO       : 'SCE_RELRO',
            Segment.PT_GNU_EH_FRAME    : 'GNU_EH_FRAME',
            Segment.PT_GNU_STACK       : 'GNU_STACK',
            Segment.PT_GNU_RELRO       : 'GNU_RELRO',
            Segment.PT_GNU_PROPERTY    : 'GNU_PROPERTY',
            Segment.PT_SCE_COMMENT     : 'SCE_COMMENT',
            Segment.PT_SCE_LIBVERSION  : 'SCE_LIBVERSION',
            Segment.PT_SCE_SEGSYM      : 'SCE_SEGSYM',
        }.get(self.TYPE, 'UNK')

    def type(self):

        if self.TYPE == Segment.PT_LOAD:
            if self.flags() & SEGPERM_EXEC:
                return 'CODE'
            if self.flags() & SEGPERM_WRITE:
                return 'DATA'
            return 'CONST'

        return {
            Segment.PT_DYNAMIC         : 'DATA',
            Segment.PT_INTERP          : 'CONST',
            Segment.PT_NOTE            : 'CONST',
            Segment.PT_PHDR            : 'CONST',
            Segment.PT_TLS             : 'BSS',
            Segment.PT_SCE_PROCPARAM   : 'CONST',
            Segment.PT_SCE_MODULEPARAM : 'CONST',
            Segment.PT_SCE_RELRO       : 'DATA',
            Segment.PT_GNU_EH_FRAME    : 'CONST',
            Segment.PT_GNU_STACK       : 'DATA',
            Segment.PT_GNU_RELRO       : 'DATA',
        }.get(self.TYPE, 'CONST')


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

    __slots__ = ('TAG', 'VALUE', 'ID', 'VERSION_MAJOR', 'VERSION_MINOR', 'NAME_OFFSET')

    # Dynamic Tags
    (DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB,
    DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI,
    DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL, DT_RELSZ, DT_RELENT, DT_PLTREL,
    DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW, DT_INIT_ARRAY, DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS, DT_ENCODING, DT_PREINIT_ARRAY,
    DT_PREINIT_ARRAYSZ, DT_SYMTAB_SHNDX)   = range(0x23)
    DT_RELRSZ                   = 0x23
    DT_RELR                     = 0x24
    DT_RELRENT                  = 0x25

    # PS4 style tags, still emitted for the *_ATTR entries
    DT_SCE_IDTABENTSZ           = 0x61000005
    DT_SCE_FINGERPRINT          = 0x61000007
    DT_SCE_ORIGINAL_FILENAME_PS4= 0x61000009
    DT_SCE_MODULE_INFO_PS4      = 0x6100000D
    DT_SCE_NEEDED_MODULE_PS4    = 0x6100000F
    DT_SCE_MODULE_ATTR          = 0x61000011
    DT_SCE_EXPORT_LIB_PS4       = 0x61000013
    DT_SCE_IMPORT_LIB_PS4       = 0x61000015
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

    # PS5 module / library tags -- packed as
    #   [63:48] id | [47:40] version major | [39:32] version minor | [31:0] strtab offset
    DT_SCE_ORIGINAL_FILENAME    = 0x61000041
    DT_SCE_MODULE_INFO          = 0x61000043
    DT_SCE_NEEDED_MODULE        = 0x61000045
    DT_SCE_EXPORT_LIB           = 0x61000047
    DT_SCE_IMPORT_LIB           = 0x61000049

    DT_SCE_HIOS                 = 0x6FFFF000
    DT_GNU_HASH                 = 0x6FFFFEF5
    DT_VERSYM                   = 0x6FFFFFF0
    DT_RELACOUNT                = 0x6FFFFFF9
    DT_RELCOUNT                 = 0x6FFFFFFA
    DT_FLAGS_1                  = 0x6FFFFFFB
    DT_VERDEF                   = 0x6FFFFFFC
    DT_VERDEFNUM                = 0x6FFFFFFD
    DT_VERNEED                  = 0x6FFFFFFE
    DT_VERNEEDNUM               = 0x6FFFFFFF

    # The tags that pack an id / version / name offset
    PACKED = (DT_SCE_MODULE_INFO, DT_SCE_NEEDED_MODULE, DT_SCE_EXPORT_LIB, DT_SCE_IMPORT_LIB,
              DT_SCE_MODULE_INFO_PS4, DT_SCE_NEEDED_MODULE_PS4,
              DT_SCE_EXPORT_LIB_PS4, DT_SCE_IMPORT_LIB_PS4)

    # The tags whose value is a bare string table offset
    STRINGS = (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_SCE_ORIGINAL_FILENAME)

    NAMES = {}

    def __init__(self, f):

        self.TAG   = struct.unpack('<Q', f.read(8))[0]
        self.VALUE = struct.unpack('<Q', f.read(8))[0]

        self.ID            = (self.VALUE >> 48) & 0xFFFF
        self.VERSION_MAJOR = (self.VALUE >> 40) & 0xFF
        self.VERSION_MINOR = (self.VALUE >> 32) & 0xFF
        self.NAME_OFFSET   = self.VALUE & 0xFFFFFFFF

    def tag(self):

        if not Dynamic.NAMES:
            for key, value in vars(Dynamic).items():
                if key.startswith('DT_') and isinstance(value, int):
                    Dynamic.NAMES.setdefault(value, key)

        return Dynamic.NAMES.get(self.TAG, 'DT_UNKNOWN_0x%x' % self.TAG)

    def lib_attribute(self):

        return {
            0x1  : 'AUTO_EXPORT',
            0x2  : 'WEAK_EXPORT',
            0x8  : 'LOOSE_IMPORT',
            0x9  : 'AUTO_EXPORT|LOOSE_IMPORT',
            0xA  : 'WEAK_EXPORT|LOOSE_IMPORT',
        }.get(self.VALUE & 0xFFFFFFFF, 'Attributes:0x%x' % (self.VALUE & 0xFFFFFFFF))

    def mod_attribute(self):

        return {
            0x0  : 'NONE',
            0x1  : 'SCE_CANT_STOP',
            0x2  : 'SCE_EXCLUSIVE_LOAD',
            0x4  : 'SCE_EXCLUSIVE_START',
            0x8  : 'SCE_CAN_RESTART',
            0x10 : 'SCE_CAN_RELOCATE',
            0x20 : 'SCE_CANT_SHARE',
        }.get(self.VALUE & 0xFFFFFFFF, 'Attributes:0x%x' % (self.VALUE & 0xFFFFFFFF))

    def comment(self, strings):

        ''' strings(offset) -> str, resolved out of the dynamic string table '''

        if self.TAG in Dynamic.STRINGS:
            return '%s | %s' % (self.tag(), strings(self.NAME_OFFSET))

        if self.TAG in (Dynamic.DT_SCE_MODULE_INFO, Dynamic.DT_SCE_NEEDED_MODULE,
                        Dynamic.DT_SCE_MODULE_INFO_PS4, Dynamic.DT_SCE_NEEDED_MODULE_PS4):
            return '%s | MID:0x%x Version:%i.%i Name:%s' % \
                   (self.tag(), self.ID, self.VERSION_MAJOR, self.VERSION_MINOR, strings(self.NAME_OFFSET))

        if self.TAG in (Dynamic.DT_SCE_EXPORT_LIB, Dynamic.DT_SCE_IMPORT_LIB,
                        Dynamic.DT_SCE_EXPORT_LIB_PS4, Dynamic.DT_SCE_IMPORT_LIB_PS4):
            return '%s | LID:0x%x Version:%i.%i Name:%s' % \
                   (self.tag(), self.ID, self.VERSION_MAJOR, self.VERSION_MINOR, strings(self.NAME_OFFSET))

        if self.TAG in (Dynamic.DT_SCE_EXPORT_LIB_ATTR, Dynamic.DT_SCE_IMPORT_LIB_ATTR):
            return '%s | LID:0x%x %s' % (self.tag(), self.ID, self.lib_attribute())

        if self.TAG == Dynamic.DT_SCE_MODULE_ATTR:
            return '%s | %s' % (self.tag(), self.mod_attribute())

        if self.TAG == Dynamic.DT_SCE_PLTREL and self.VALUE == 0x7:
            return '%s | 0x%x | DT_RELA' % (self.tag(), self.VALUE)

        return '%s | 0x%x' % (self.tag(), self.VALUE)


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

    def bind(self):

        return self.INFO >> 0x4

    def kind(self):

        return self.INFO & 0xF

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
        }.get(self.INFO, 'Info:0x%x' % self.INFO)


class Relocation:

    __slots__ = ('OFFSET', 'INFO', 'ADDEND', 'INDEX', 'CODE')

    # PS5 (X86_64) Relocation Codes
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

    NAMES = {}

    def __init__(self, f):

        self.OFFSET = struct.unpack('<Q', f.read(8))[0]
        self.INFO   = struct.unpack('<Q', f.read(8))[0]
        self.ADDEND = struct.unpack('<q', f.read(8))[0]

        # ELF64 r_info: high 32 bits are the symbol index, low 32 the relocation code
        self.INDEX  = self.INFO >> 32
        self.CODE   = self.INFO & 0xFFFFFFFF

    def type(self):

        if not Relocation.NAMES:
            for key, value in vars(Relocation).items():
                if key.startswith('R_X86_64_') and isinstance(value, int):
                    Relocation.NAMES.setdefault(value, key)

        return Relocation.NAMES.get(self.CODE, 'Missing PS5 Relocation Type!!! (0x%x)' % self.CODE)


# PROGRAM START

# Open File Dialog...
def accept_file(f, filename):

    try:
        ps5 = Binary(f)
    except:
        return 0

    # No Kernels
    if ps5.E_MACHINE == Binary.EM_X86_64 and ps5.E_START_ADDR < 0xFFFFFFFF82200000 and ps5.is_ps5():
        return { 'format': 'PS5 - ' + ps5.type(),
                 'options': ACCEPT_FIRST }
    return 0


# Since IDA cannot create a compatibility layer to save its life...
def find_binary(address, end, search, format, flags):

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


def read_nids(location):

    ''' aerolib.csv is "<nid> <name>" per line -- split once so that names are
        never mangled by a stray separator '''

    nids = {}
    with open(location, 'r') as database:
        for line in database:
            key, _, value = line.rstrip('\r\n').partition(' ')
            if key and value:
                nids[key] = value
    return nids


# Load NID Library...
def load_nids(location):

    try:
        return read_nids(location)

    except IOError:
        retry = idaapi.ask_file(0, 'aerolib.csv|*.csv|All files (*.*)|*.*', 'Please gimme your aerolib.csv file')

        if retry is not None:
            try:
                nids = read_nids(retry)
                shutil.copy2(retry, location)
                return nids
            except:
                print('Ok, no NIDs for you!')
        else:
            print('Ok, no NIDs for you!')

    return {}


# Pablo's Scripts
def pablo(mode, address, end, search):

    code = idaapi.get_segm_by_name('CODE')

    while address < end:
        address = find_binary(address, end, search, 0x10, SEARCH_DOWN)

        if address == BADADDR:
            break

        if code is not None and address > code.end_ea:
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


# --------------------------------------------------------------------------------------------------------
# PS5 native (SELF) syscall table, lifted from sv_syscallnames of the Native
# sysentvec.  730 entries -- the PS4/FreeBSD ABI table is a different, shorter
# one and its numbering does NOT match.
PS5_SYSCALLS = [
        'syscall', 'exit', 'fork', 'read', 'write', 'open', 'close', 'wait4', 'compat.creat', 'link', 'unlink',
        'obs_execv', 'chdir', 'fchdir', 'mknod', 'chmod', 'chown', 'obs_{', 'compat4.getfsstat', 'compat.lseek',
        'getpid', 'mount', 'unmount', 'setuid', 'getuid', 'geteuid', 'ptrace', 'recvmsg', 'sendmsg', 'recvfrom',
        'accept', 'getpeername', 'getsockname', 'access', 'chflags', 'fchflags', 'sync', 'kill', 'compat.stat',
        'getppid', 'compat.lstat', 'dup', 'compat10.pipe', 'getegid', 'profil', 'ktrace', 'compat.sigaction',
        'getgid', 'compat.sigprocmask', 'getlogin', 'setlogin', 'obs_{', 'compat.sigpending', 'sigaltstack',
        'ioctl', 'reboot', 'revoke', 'symlink', 'readlink', 'execve', 'umask', 'chroot', 'compat.fstat',
        'compat.getkerninfo', 'compat.getpagesize', 'msync', 'vfork', 'obs_vread', 'obs_vwrite', 'sbrk', 'sstk',
        'compat.mmap', 'obs_{', 'munmap', 'mprotect', 'madvise', 'obs_vhangup', 'obs_vlimit', 'mincore',
        'getgroups', 'setgroups', 'getpgrp', 'setpgid', 'setitimer', 'compat.wait', 'swapon', 'getitimer',
        'compat.gethostname', 'compat.sethostname', 'getdtablesize', 'dup2', '\x2391', 'fcntl', 'select', '\x2394',
        'fsync', 'setpriority', 'socket', 'connect', 'netcontrol', 'getpriority', 'netabort', 'netgetsockinfo',
        'compat.sigreturn', 'bind', 'setsockopt', 'listen', 'obs_vtimes', 'compat.sigvec', 'compat.sigblock',
        'compat.sigsetmask', 'compat.sigsuspend', 'compat.sigstack', 'socketex', 'socketclose', 'obs_vtrace',
        'gettimeofday', 'getrusage', 'getsockopt', '\x23119', 'readv', 'writev', 'settimeofday', 'fchown', 'fchmod',
        'netgetiflist', 'setreuid', 'setregid', 'rename', 'compat.truncate', 'compat.ftruncate', 'flock', 'mkfifo',
        'sendto', 'shutdown', 'socketpair', 'mkdir', 'rmdir', 'utimes', 'obs_4.2', 'adjtime', 'kqueueex',
        'compat.gethostid', 'compat.sethostid', 'compat.getrlimit', 'compat.setrlimit', 'compat.killpg', 'setsid',
        'obs_{', 'compat.quota', 'compat.getsockname', '\x23151', '\x23152', '\x23153', 'nlm_syscall', 'nfssvc',
        'compat.getdirentries', 'compat4.statfs', 'compat4.fstatfs', '\x23159', 'obs_{', 'obs_{',
        'compat4.getdomainname', 'compat4.setdomainname', 'compat4.uname', 'sysarch', 'rtprio', '\x23167', '\x23168',
        'semsys', 'msgsys', 'shmsys', '\x23172', 'compat6.pread', 'compat6.pwrite', 'obs_{', 'obs_{', '\x23177', '\x23178',
        '\x23179', '\x23180', 'setgid', 'setegid', 'seteuid', '\x23184', '\x23185', '\x23186', '\x23187', 'stat', 'fstat', 'lstat',
        'pathconf', 'fpathconf', '\x23193', 'getrlimit', 'setrlimit', 'getdirentries', 'compat6.mmap', '__syscall',
        'compat6.lseek', 'compat6.truncate', 'compat6.ftruncate', '__sysctl', 'mlock', 'munlock', 'obs_{',
        'futimes', 'getpgid', '\x23208', 'poll', 'lkmnosys', 'lkmnosys', 'lkmnosys', 'lkmnosys', 'lkmnosys',
        'lkmnosys', 'lkmnosys', 'lkmnosys', 'lkmnosys', 'lkmnosys', 'compat7.__semctl', 'semget', 'semop', '\x23223',
        'compat7.msgctl', 'msgget', 'msgsnd', 'msgrcv', 'shmat', 'compat7.shmctl', 'shmdt', 'shmget',
        'clock_gettime', 'clock_settime', 'clock_getres', 'ktimer_create', 'ktimer_delete', 'ktimer_settime',
        'ktimer_gettime', 'ktimer_getoverrun', 'nanosleep', 'ffclock_getcounter', 'ffclock_setestimate',
        'ffclock_getestimate', '\x23244', '\x23245', '\x23246', 'clock_getcpuclockid2', 'obs_{', '\x23249', 'minherit',
        'rfork', 'obs_{', 'issetugid', 'lchown', 'aio_read', 'aio_write', 'obs_{', '\x23258', '\x23259', '\x23260', '\x23261',
        '\x23262', '\x23263', '\x23264', '\x23265', '\x23266', '\x23267', '\x23268', '\x23269', '\x23270', '\x23271', 'getdents', '\x23273',
        'lchmod', 'netbsd_lchown', 'lutimes', 'netbsd_msync', 'obs_{', 'obs_{', 'obs_{', '\x23281', '\x23282', '\x23283',
        '\x23284', '\x23285', '\x23286', '\x23287', '\x23288', 'preadv', 'pwritev', '\x23291', '\x23292', '\x23293', '\x23294', '\x23295',
        '\x23296', 'compat4.fhstatfs', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'kldload', 'kldunload',
        'kldfind', 'kldnext', 'kldstat', 'kldfirstmod', 'getsid', 'setresuid', 'setresgid', 'obs_signanosleep',
        'aio_return', 'aio_suspend', 'aio_cancel', 'aio_error', 'compat6.aio_read', 'compat6.aio_write',
        'compat6.lio_listio', 'yield', 'obs_thr_sleep', 'obs_thr_wakeup', 'mlockall', 'munlockall', '__getcwd',
        'sched_setparam', 'sched_getparam', 'sched_setscheduler', 'sched_getscheduler', 'sched_yield',
        'sched_get_priority_max', 'sched_get_priority_min', 'sched_rr_get_interval', 'utrace', 'compat4.sendfile',
        'kldsym', 'obs_{', 'nnpfs_syscall', 'sigprocmask', 'sigsuspend', 'compat4.sigaction', 'sigpending',
        'compat4.sigreturn', 'sigtimedwait', 'sigwaitinfo', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{',
        'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'aio_waitcomplete', 'getresuid', 'getresgid',
        'kqueue', 'kevent', '\x23364', '\x23365', '\x23366', '\x23367', '\x23368', '\x23369', '\x23370', 'obs_{', 'obs_{', 'obs_{',
        '__setugid', '\x23375', 'obs_{', 'afs3_syscall', 'nmount', 'mtypeprotect', '\x23380', '\x23381', '\x23382', '\x23383',
        '__mac_get_proc', '__mac_set_proc', '__mac_get_fd', '__mac_get_file', '__mac_set_fd', '__mac_set_file',
        'kenv', 'lchflags', 'uuidgen', 'sendfile', 'mac_syscall', 'getfsstat', 'statfs', 'fstatfs', 'obs_{',
        '\x23399', 'ksem_close', 'ksem_post', 'ksem_wait', 'ksem_trywait', 'ksem_init', 'ksem_open', 'ksem_unlink',
        'ksem_getvalue', 'ksem_destroy', '__mac_get_pid', '__mac_get_link', '__mac_set_link', 'obs_{', 'obs_{',
        'obs_{', '__mac_execve', 'sigaction', 'sigreturn', '\x23418', '\x23419', '\x23420', 'getcontext', 'setcontext',
        'swapcontext', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'sigwait', 'thr_create', 'thr_exit',
        'thr_self', 'thr_kill', '\x23434', '\x23435', 'obs_{', 'obs_{', 'obs_{', 'obs_{', '\x23440', 'ksem_timedwait',
        'thr_suspend', 'thr_wake', 'kldunloadf', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'obs_{',
        'obs_{', 'obs_{', '_umtx_op', 'thr_new', 'sigqueue', 'kmq_open', 'kmq_setattr', 'kmq_timedreceive',
        'kmq_timedsend', 'kmq_notify', 'kmq_unlink', 'obs_{', 'thr_set_name', 'aio_fsync', 'rtprio_thread', '\x23467',
        '\x23468', '\x23469', '\x23470', 'obs_{', 'obs_{', 'obs_{', 'obs_{', 'pread', 'pwrite', 'mmap', 'lseek', 'truncate',
        'ftruncate', 'thr_kill2', 'shm_open', 'shm_unlink', 'cpuset', 'cpuset_setid', 'cpuset_getid',
        'cpuset_getaffinity', 'cpuset_setaffinity', 'obs_{', 'fchmodat', 'fchownat', 'obs_{', 'fstatat',
        'futimesat', 'linkat', 'mkdirat', 'mkfifoat', 'mknodat', 'openat', 'obs_{', 'renameat', 'symlinkat',
        'unlinkat', 'obs_{', 'gssd_syscall', 'obs_{', 'obs_{', 'obs_{', 'obs_{', '__semctl', 'msgctl', 'shmctl',
        'obs_{', 'obs_cap_new', '__cap_rights_get', 'cap_enter', 'cap_getmode', 'obs_{', 'pdkill', 'pdgetpid',
        '\x23521', 'pselect', 'obs_{', 'obs_{', 'rctl_get_racct', 'rctl_get_rules', 'rctl_get_limits',
        'rctl_add_rule', 'rctl_remove_rule', 'obs_{', 'obs_{', 'regmgr_call', 'jitshm_create', 'jitshm_alias',
        'dl_get_list', 'dl_get_info', 'obs_{', 'evf_create', 'evf_delete', 'evf_open', 'evf_close', 'evf_wait',
        'evf_trywait', 'evf_set', 'evf_clear', 'evf_cancel', 'query_memory_protection', 'batch_map', 'osem_create',
        'osem_delete', 'osem_open', 'osem_close', 'osem_wait', 'osem_trywait', 'osem_post', 'osem_cancel',
        'namedobj_create', 'namedobj_delete', 'set_vm_container', 'debug_init', 'suspend_process',
        'resume_process', 'opmc_enable', 'opmc_disable', 'opmc_set_ctl', 'opmc_set_ctr', 'opmc_get_ctr',
        'budget_create', 'budget_delete', 'budget_get', 'budget_set', 'virtual_query', 'mdbg_call',
        'obs_sblock_create', 'obs_sblock_delete', 'obs_sblock_enter', 'obs_sblock_exit', 'obs_sblock_xenter',
        'obs_sblock_xexit', 'obs_eport_create', 'obs_eport_delete', 'obs_eport_trigger', 'obs_eport_open',
        'obs_eport_close', 'is_in_sandbox', 'dmem_container', 'get_authinfo', 'mname', 'dynlib_dlopen',
        'dynlib_dlclose', 'dynlib_dlsym', 'dynlib_get_list', 'dynlib_get_info', 'dynlib_load_prx',
        'dynlib_unload_prx', 'dynlib_do_copy_relocations', 'dynlib_prepare_dlclose', 'dynlib_get_proc_param',
        'dynlib_process_needed_and_relocate', 'sandbox_path', 'mdbg_service', 'randomized_path', 'rdup',
        'dl_get_metadata', 'workaround8849', 'is_development_mode', 'get_self_auth_info', 'dynlib_get_info_ex',
        'budget_getid', 'budget_get_ptype', 'get_paging_stats_of_all_threads', 'get_proc_type_info',
        'get_resident_count', 'prepare_to_suspend_process', 'get_resident_fmem_count', 'thr_get_name', 'set_gpo',
        'get_paging_stats_of_all_objects', 'test_debug_rwmem', 'free_stack', 'suspend_system', 'ipmimgr_call',
        'get_gpo', 'get_vm_map_timestamp', 'opmc_set_hw', 'opmc_get_hw', 'get_cpu_usage_all', 'mmap_dmem',
        'physhm_open', 'physhm_unlink', 'resume_internal_hdd', 'thr_suspend_ucontext', 'thr_resume_ucontext',
        'thr_get_ucontext', 'thr_set_ucontext', 'set_timezone_info', 'set_phys_fmem_limit', 'utc_to_localtime',
        'localtime_to_utc', 'set_uevt', 'get_cpu_usage_proc', 'get_map_statistics', 'set_chicken_switches', '\x23644',
        '\x23645', 'get_kernel_mem_statistics', 'get_sdk_compiled_version', 'app_state_change',
        'dynlib_get_obj_member', 'budget_get_ptype_of_budget', 'prepare_to_resume_process', 'process_terminate',
        'blockpool_open', 'blockpool_map', 'blockpool_unmap', 'dynlib_get_info_for_libdbg', 'blockpool_batch',
        'fdatasync', 'dynlib_get_list2', 'dynlib_get_info2', 'aio_submit', 'aio_multi_delete', 'aio_multi_wait',
        'aio_multi_poll', 'aio_get_data', 'aio_multi_cancel', 'get_bio_usage_all', 'aio_create', 'aio_submit_cmd',
        'aio_init', 'get_page_table_stats', 'dynlib_get_list_for_libdbg', 'blockpool_move', 'virtual_query_all',
        'reserve_2mb_page', 'cpumode_yield', 'wait6', 'cap_rights_limit', 'cap_ioctls_limit', 'cap_ioctls_get',
        'cap_fcntls_limit', 'cap_fcntls_get', 'bindat', 'connectat', 'chflagsat', 'accept4', 'pipe2', 'aio_mlock',
        'procctl', 'ppoll', 'futimens', 'utimensat', 'numa_getaffinity', 'numa_setaffinity', '\x23695', '\x23696',
        '\x23697', '\x23698', '\x23699', 'apr_submit', 'apr_resolve', 'apr_stat', 'apr_wait', 'apr_ctrl',
        'get_phys_page_size', 'begin_app_mount', 'end_app_mount', 'fsc2h_ctrl', 'streamwrite', 'app_save',
        'app_restore', 'saved_app_delete', 'get_ppr_sdk_compiled_version', 'notify_app_event', 'ioreq', 'openintr',
        'dl_get_info_2', 'acinfo_add', 'acinfo_delete', 'acinfo_get_all_for_coredump', 'ampr_ctrl_debug',
        'workspace_ctrl', 'notify_a53_bind_progress', 'dynlib_get_lid_mid_info', 'mmap2',
        'get_aio_debug_submit_info', 'get_aio_debug_request_info', 'virtual_query_by_pid',
        'get_resident_fmem_count2'
]


def make_struct(name, members):

    ''' Cosmetic table overlays -- silently skipped on IDA builds that dropped
        the legacy struct API '''

    try:
        entry = idc.get_struc_id(name)
        if entry not in (None, BADADDR, -1):
            return entry

        entry = idc.add_struc(BADADDR, name, False)
        if entry in (None, BADADDR, -1):
            return None

        location = 0x0
        for (member, comment, size) in members:
            flags = idaapi.get_flags_by_size(size)

            if member in ('addend', 'offset'):
                idc.add_struc_member(entry, member, location, flags | FF_0OFF, BADADDR, size, BADADDR, 0, REF_OFF64)
            else:
                idc.add_struc_member(entry, member, location, flags, BADADDR, size)

            idc.set_member_cmt(entry, location, comment, False)
            location += size

        return entry
    except:
        return None


def apply_struct(address, size, entry):

    try:
        if entry not in (None, BADADDR, -1):
            idaapi.create_struct(address, size, entry)
    except:
        pass


def import_symbol(library, address, name):

    ''' Register an imported function so IDA groups it under its library '''

    try:
        node = idaapi.netnode(str(library), 0, True)
        node.supset(ea2node(address), name)

        if sys.platform.startswith('win'):
            try:
                dll = ctypes.windll['ida64.dll']
            except:
                dll = ctypes.windll['ida.dll']
        else:
            ext = '.dylib' if sys.platform == 'darwin' else '.so'
            try:
                dll = ctypes.cdll['libida64' + ext]
            except:
                dll = ctypes.cdll['libida' + ext]

        dll.import_module.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong,
                                      ctypes.c_char_p, ctypes.c_char_p]
        dll.import_module(library.encode(), None, node.index(), None, b'linux')
    except:
        pass


# Load Input Binary...
def load_file(f, neflags, format):

    log('PS5 Module Loader')
    ps5 = Binary(f)

    loads = [segm for segm in ps5.E_SEGMENTS if segm.TYPE == Segment.PT_LOAD and segm.MEM_SIZE]

    min_vaddr = min(segm.MEM_ADDR for segm in loads) if loads else (ps5.E_START_ADDR & ~0xFFF)

    # The first executable load is what people think of as "the base"
    original_base = min_vaddr
    for segm in loads:
        if segm.flags() & SEGPERM_EXEC:
            original_base = segm.MEM_ADDR
            break

    use_custom, custom_base = get_custom_base_address(original_base)

    if use_custom:
        base_offset = custom_base - min_vaddr
        log('Custom rebase: 0x%x -> 0x%x (offset: %+d)' % (min_vaddr, custom_base, base_offset))
    else:
        base_offset = 0
        log('Using original virtual addresses')

    # PS5 Processor, Compiler, Library...
    bitness = ps5.procomp('metapc', CM_N64 | CM_M_NN | CM_CC_FASTCALL, 'ps5_errno')

    # Load Aerolib...
    nids = load_nids(idc.idadir() + '/loaders/aerolib.csv')
    log('Loaded %i NIDs' % len(nids))

    # --------------------------------------------------------------------------------------------------------
    # Virtual address -> file offset, over the loadable segments only
    def v2f(va):
        for segm in loads:
            if segm.MEM_ADDR <= va < segm.MEM_ADDR + segm.FILE_SIZE:
                return segm.OFFSET + (va - segm.MEM_ADDR)
        return None

    def blob(va, size):
        ''' Pull `size` bytes living at virtual address `va` out of the input file '''
        offset = v2f(va)
        if offset is None:
            return b''
        f.seek(offset)
        return f.read(size)

    # --------------------------------------------------------------------------------------------------------
    # Segment Loading...
    used = {}
    for segm in loads:

        address = segm.MEM_ADDR + base_offset

        name = segm.name()
        if name in used:
            used[name] += 1
            name = '%s%i' % (name, used[name])
        else:
            used[name] = 0

        if base_offset:
            log('Processing %s Segment at 0x%x (was 0x%x)...' % (name, address, segm.MEM_ADDR))
        else:
            log('Processing %s Segment at 0x%x...' % (name, address))

        if segm.FILE_SIZE:
            f.file2base(segm.OFFSET, address, address + segm.FILE_SIZE, FILEREG_PATCHABLE)

        idaapi.add_segm(0, address, address + segm.MEM_SIZE, name, segm.type(),
                        ADDSEG_NOTRUNC | ADDSEG_FILLGAP)

        idc.set_segm_addressing(address, bitness)
        idc.set_segm_alignment(address, segm.alignment())
        idc.set_segm_attr(address, SEGATTR_PERM, segm.flags())

        # Uninitialised tail (.bss)
        if segm.MEM_SIZE > segm.FILE_SIZE:
            log('  .bss tail 0x%x - 0x%x' % (address + segm.FILE_SIZE, address + segm.MEM_SIZE))

    # --------------------------------------------------------------------------------------------------------
    # Informational segments that live outside any load
    for segm in ps5.E_SEGMENTS:

        if segm.TYPE == Segment.PT_SCE_MODULEPARAM and segm.FILE_SIZE >= 0x18:
            f.seek(segm.OFFSET)
            raw = f.read(min(segm.FILE_SIZE, 0x20))
            if len(raw) < 0x18:
                continue
            size, magic, version = struct.unpack_from('<QII', raw, 0x0)
            if magic == 0x3C13F4BF:
                sdk = struct.unpack_from('<I', raw, 0x14)[0] if len(raw) >= 0x18 else 0
                log('SCE_MODULEPARAM  magic:0x%x version:%i sdk:%X.%02X.%02X.%02X' %
                      (magic, version, (sdk >> 24) & 0xFF, (sdk >> 16) & 0xFF, (sdk >> 8) & 0xFF, sdk & 0xFF))
                if segm.MEM_ADDR:
                    idc.set_name(segm.MEM_ADDR + base_offset, 'SCE_MODULE_PARAM',
                                 SN_NOCHECK | SN_NOWARN | SN_FORCE)

        elif segm.TYPE == Segment.PT_SCE_PROCPARAM and segm.MEM_ADDR:
            idc.set_name(segm.MEM_ADDR + base_offset, 'SCE_PROCESS_PARAM',
                         SN_NOCHECK | SN_NOWARN | SN_FORCE)

        elif segm.TYPE == Segment.PT_SCE_COMMENT and segm.FILE_SIZE:
            f.seek(segm.OFFSET)
            raw = f.read(segm.FILE_SIZE)
            text = raw[0xC:].split(b'\x00')[0].decode('utf8', 'replace')
            if text:
                log('SCE_COMMENT      %s' % text)

        elif segm.TYPE == Segment.PT_NOTE and segm.FILE_SIZE >= 0x10:
            f.seek(segm.OFFSET)
            raw = f.read(segm.FILE_SIZE)
            if len(raw) < 0x10:
                continue
            namesz, descsz, kind = struct.unpack_from('<III', raw, 0x0)
            note = raw[0xC:0xC + namesz].split(b'\x00')[0].decode('utf8', 'replace')
            desc = raw[0xC + ((namesz + 3) & ~3):][:descsz]
            if note == 'GNU' and kind == 0x3:
                log('GNU Build ID     %s' % ''.join('%02x' % byte for byte in bytearray(desc)))

    code = idaapi.get_segm_by_name('CODE')

    # --------------------------------------------------------------------------------------------------------
    # Dynamic Segment
    #
    # Unlike the PS4, every table address below is a plain virtual address that
    # falls inside one of the PT_LOADs above -- there is no PT_SCE_DYNLIBDATA
    # and no "offset from the start of the blob" indirection.
    dynamic = next((segm for segm in ps5.E_SEGMENTS if segm.TYPE == Segment.PT_DYNAMIC), None)

    if dynamic is None:
        log('No PT_DYNAMIC -- nothing left to do')
        return 1

    f.seek(dynamic.OFFSET)
    tags = []
    for entry in range(int(dynamic.FILE_SIZE / 0x10)):
        tag = Dynamic(f)
        tags.append(tag)
        if tag.TAG == Dynamic.DT_NULL:
            break

    def scalar(*candidates):
        for tag in tags:
            if tag.TAG in candidates:
                return tag.VALUE
        return None

    STRTAB   = scalar(Dynamic.DT_STRTAB, Dynamic.DT_SCE_STRTAB)
    STRSZ    = scalar(Dynamic.DT_STRSZ, Dynamic.DT_SCE_STRSZ) or 0
    SYMTAB   = scalar(Dynamic.DT_SYMTAB, Dynamic.DT_SCE_SYMTAB)
    SYMENT   = scalar(Dynamic.DT_SYMENT, Dynamic.DT_SCE_SYMENT) or 0x18
    SYMTABSZ = scalar(Dynamic.DT_SCE_SYMTABSZ)
    HASHTAB  = scalar(Dynamic.DT_HASH, Dynamic.DT_SCE_HASH)
    HASHSZ   = scalar(Dynamic.DT_SCE_HASHSZ) or 0
    JMPTAB   = scalar(Dynamic.DT_JMPREL, Dynamic.DT_SCE_JMPREL)
    JMPTABSZ = scalar(Dynamic.DT_PLTRELSZ, Dynamic.DT_SCE_PLTRELSZ) or 0
    RELATAB  = scalar(Dynamic.DT_RELA, Dynamic.DT_SCE_RELA)
    RELATABSZ= scalar(Dynamic.DT_RELASZ, Dynamic.DT_SCE_RELASZ) or 0
    PLTGOT   = scalar(Dynamic.DT_PLTGOT, Dynamic.DT_SCE_PLTGOT)
    INIT     = scalar(Dynamic.DT_INIT)
    FINI     = scalar(Dynamic.DT_FINI)

    # DT_SCE_SYMTABSZ is the only thing that ever states how long .dynsym is;
    # fall back on the hash table's nchain, then on the gap up to .dynstr
    if not SYMTABSZ and SYMTAB is not None:
        if HASHTAB is not None:
            header = blob(HASHTAB, 0x8)
            if len(header) == 0x8:
                nchain = struct.unpack_from('<I', header, 0x4)[0]
                SYMTABSZ = nchain * SYMENT
        if not SYMTABSZ and STRTAB is not None and STRTAB > SYMTAB:
            SYMTABSZ = STRTAB - SYMTAB

    strtab = blob(STRTAB, STRSZ) if STRTAB is not None else b''

    def strings(offset):
        if offset >= len(strtab):
            return ''
        end = strtab.find(b'\x00', offset)
        end = len(strtab) if end < 0 else end
        return strtab[offset:end].decode('utf8', 'replace')

    # Modules and Libraries
    modules   = {}
    libraries = {}

    for tag in tags:
        if tag.TAG in (Dynamic.DT_SCE_NEEDED_MODULE, Dynamic.DT_SCE_NEEDED_MODULE_PS4):
            modules[tag.ID] = strings(tag.NAME_OFFSET)
        elif tag.TAG in (Dynamic.DT_SCE_EXPORT_LIB, Dynamic.DT_SCE_IMPORT_LIB,
                         Dynamic.DT_SCE_EXPORT_LIB_PS4, Dynamic.DT_SCE_IMPORT_LIB_PS4):
            libraries[tag.ID] = strings(tag.NAME_OFFSET)

    # The module itself is always module id 0
    for tag in tags:
        if tag.TAG in (Dynamic.DT_SCE_MODULE_INFO, Dynamic.DT_SCE_MODULE_INFO_PS4):
            modules.setdefault(0x0, strings(tag.NAME_OFFSET))
            log('Module           %s (v%i.%i)' % (strings(tag.NAME_OFFSET),
                                                      tag.VERSION_MAJOR, tag.VERSION_MINOR))
        elif tag.TAG == Dynamic.DT_SCE_ORIGINAL_FILENAME:
            log('Original Path    %s' % strings(tag.NAME_OFFSET))
        elif tag.TAG == Dynamic.DT_SONAME:
            log('SONAME           %s' % strings(tag.NAME_OFFSET))

    needed = sorted(set(name for mid, name in modules.items() if mid))
    log('Needed Modules   %s' % (', '.join(needed) or '(none)'))
    log('Libraries        %i' % len(libraries))

    # Comment and structure the dynamic table itself
    struct_tag = make_struct('Tag', [('tag', 'Tag', 0x8), ('value', 'Value', 0x8)])
    location = dynamic.MEM_ADDR + base_offset

    for entry, tag in enumerate(tags):
        apply_struct(location + (entry * 0x10), 0x10, struct_tag)
        idc.set_cmt(location + (entry * 0x10), tag.comment(strings), False)

    if dynamic.MEM_ADDR:
        idc.set_name(location, '_DYNAMIC', SN_NOCHECK | SN_NOWARN | SN_FORCE)

    # --------------------------------------------------------------------------------------------------------
    # Dynamic Symbol Table
    symbols = []

    if SYMTAB is not None and SYMTABSZ:
        struct_symbol = make_struct('Symbol', [('name',   'Name (String Index)',   0x4),
                                               ('info',   'Info (Binding : Type)', 0x1),
                                               ('other',  'Other',                 0x1),
                                               ('shtndx', 'Section Index',         0x2),
                                               ('value',  'Value',                 0x8),
                                               ('size',   'Size',                  0x8)])

        location = SYMTAB + base_offset
        offset   = v2f(SYMTAB)

        if offset is not None:
            idc.add_entry(location, location, '.dynsym', False)
            f.seek(offset)

            for entry in range(int(SYMTABSZ / SYMENT)):
                symbol = Symbol(f)
                symbols.append(symbol)
                apply_struct(location + (entry * SYMENT), SYMENT, struct_symbol)
                idc.set_cmt(location + (entry * SYMENT),
                            '%s | %s' % (strings(symbol.NAME), symbol.info()), False)

    log('Dynamic Symbols  %i' % len(symbols))

    if STRTAB is not None:
        idc.add_entry(STRTAB + base_offset, STRTAB + base_offset, '.dynstr', False)

    # --------------------------------------------------------------------------------------------------------
    # NID -> name, remembering which library a symbol belongs to
    def demangle(name):
        nid, lid, mid = split_nid(name)
        return nids.get(nid, name), lid, mid

    def library_of(lid):
        return libraries.get(lid, '')

    # --------------------------------------------------------------------------------------------------------
    # Resolve Export Symbols
    exported = 0
    unknown  = 0

    for entry, symbol in enumerate(symbols):

        if not symbol.NAME or not symbol.VALUE or not symbol.SHINDEX:
            continue

        raw = strings(symbol.NAME)
        name, lid, mid = demangle(raw)

        if name == raw and lid is not None:
            unknown += 1

        address = symbol.VALUE + base_offset

        try:
            if symbol.kind() == 0x2:  # STT_FUNC
                if idaapi.get_func_num(address) > 0:
                    idc.del_func(address)
                idc.add_func(address)
                idc.add_entry(address, address, name, True)
            else:
                idc.add_entry(address, address, name, False)

            idc.set_name(address, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            idc.set_cmt(address, 'NID: %s | %s | %s' % (raw, symbol.info(), library_of(lid)), False)
            exported += 1
        except:
            pass

    log('Exports          %i resolved, %i unknown NIDs' % (exported - unknown, unknown))

    # --------------------------------------------------------------------------------------------------------
    # Jump Table (.rela.plt)
    if JMPTAB is not None and JMPTABSZ:

        struct_jump = make_struct('Jump', [('offset', 'Offset (Virtual Address)',            0x8),
                                           ('info',   'Info (Symbol Index : Relocation Code)', 0x8),
                                           ('addend', 'AddEnd',                              0x8)])

        location = JMPTAB + base_offset
        offset   = v2f(JMPTAB)

        if offset is not None:
            idc.add_entry(location, location, '.rela.plt', False)
            f.seek(offset)

            if PLTGOT is not None:
                idc.set_name(PLTGOT + base_offset, '.got.plt', SN_NOCHECK | SN_NOWARN | SN_FORCE)

            imported = 0

            for entry in range(int(JMPTABSZ / 0x18)):
                rel = Relocation(f)
                apply_struct(location + (entry * 0x18), 0x18, struct_jump)
                idc.set_cmt(location + (entry * 0x18), rel.type(), False)

                if rel.INDEX >= len(symbols):
                    continue

                raw = strings(symbols[rel.INDEX].NAME)
                name, lid, mid = demangle(raw)
                slot = rel.OFFSET + base_offset

                # The unrelocated slot points at the PLT thunk's `push index`;
                # the thunk itself starts six bytes earlier, at `jmp [rip+X]`
                real = idc.get_qword(slot) + base_offset

                if idc.get_wide_byte(real) == 0x68 and \
                   idc.get_wide_byte(real - 0x6) == 0xFF and idc.get_wide_byte(real - 0x5) == 0x25:
                    real -= 0x6

                try:
                    idc.add_func(real)
                    idc.set_name(real, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)
                    idc.set_cmt(real, 'NID: %s' % raw, False)
                except:
                    pass

                try:
                    idc.set_name(slot, '__imp_' + name, SN_NOCHECK | SN_NOWARN | SN_FORCE)
                    idaapi.create_data(slot, FF_QWORD, 0x8, BADNODE)
                except:
                    pass

                import_symbol(library_of(lid) or modules.get(mid, 'unknown'), real, name)
                imported += 1

            log('Imports          %i' % imported)

    # --------------------------------------------------------------------------------------------------------
    # Relocation Table (.rela.dyn)
    if RELATAB is not None and RELATABSZ:

        struct_rela = make_struct('Relocation', [('offset', 'Offset (Virtual Address)',              0x8),
                                                 ('info',   'Info (Symbol Index : Relocation Code)', 0x8),
                                                 ('addend', 'AddEnd',                               0x8)])

        location = RELATAB + base_offset
        offset   = v2f(RELATAB)

        if offset is not None:
            idc.add_entry(location, location, '.rela.dyn', False)
            f.seek(offset)

            for entry in range(int(RELATABSZ / 0x18)):
                rel = Relocation(f)
                apply_struct(location + (entry * 0x18), 0x18, struct_rela)
                idc.set_cmt(location + (entry * 0x18), rel.type(), False)

                target = rel.OFFSET + base_offset

                # Base + AddEnd (B + A)
                if rel.CODE in (Relocation.R_X86_64_RELATIVE, Relocation.R_X86_64_RELATIVE64,
                                Relocation.R_X86_64_IRELATIVE):
                    try:
                        idaapi.put_qword(target, rel.ADDEND + base_offset)
                        idaapi.create_data(target, FF_QWORD, 0x8, BADNODE)
                    except:
                        pass
                    continue

                # TLS Object
                if rel.CODE in (Relocation.R_X86_64_DTPMOD64, Relocation.R_X86_64_DTPOFF64,
                                Relocation.R_X86_64_TPOFF64):
                    idc.set_name(target, 'tls_access_struct', SN_NOCHECK | SN_NOWARN | SN_FORCE)
                    continue

                if rel.INDEX >= len(symbols):
                    continue

                # Symbol Value + AddEnd (S + A)
                raw = strings(symbols[rel.INDEX].NAME)
                name, lid, mid = demangle(raw)

                try:
                    idc.set_cmt(target, 'NID: %s | %s' % (raw, library_of(lid)), False)
                    idc.set_name(target, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)
                    idaapi.create_data(target, FF_QWORD, 0x8, BADNODE)
                except:
                    pass

    # --------------------------------------------------------------------------------------------------------
    # Hash Table
    if HASHTAB is not None and HASHSZ:
        struct_hash = make_struct('Hash', [('bucket',  'Bucket',  0x2),
                                           ('chain',   'Chain',   0x2),
                                           ('buckets', 'Buckets', 0x2),
                                           ('chains',  'Chains',  0x2)])

        location = HASHTAB + base_offset
        idc.add_entry(location, location, '.hash', False)

        for entry in range(int(HASHSZ / 0x8)):
            apply_struct(location + (entry * 0x8), 0x8, struct_hash)

    # --------------------------------------------------------------------------------------------------------
    # Entry Points
    if INIT:
        idc.add_entry(INIT + base_offset, INIT + base_offset, '.init_proc', True)
    if FINI:
        idc.add_entry(FINI + base_offset, FINI + base_offset, '.term_proc', True)

    if ps5.E_START_ADDR:
        address = ps5.E_START_ADDR + base_offset
        idc.add_entry(address, address, 'start', True)

    # Set No Return for __stack_chk_fail...
    try:
        function = idaapi.get_func(idc.get_name_ea_simple('__stack_chk_fail'))
        function.flags |= FUNC_NORET
        idaapi.update_func(function)
    except:
        pass

    # --------------------------------------------------------------------------------------------------------
    # Pablo's Scripts
    if code is not None:
        try:
            log('Processing Pablo\'s Push script...')

            # Script 1) Push it real good...
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

        except:
            pass

    # --------------------------------------------------------------------------------------------------------
    # Syscall Commenter
    #
    # PS5 stubs look like     mov eax, <number> ; mov r10, rcx ; syscall
    #                     48 C7 C0 nn nn nn nn   49 89 CA       0F 05
    # older/short ones use    mov eax, <number>  (B8 nn nn nn nn) instead.
    if code is not None:
        try:
            log('Processing Syscall Commenter...')

            address = code.start_ea
            end     = code.end_ea
            found   = 0

            while address < end:
                address = find_binary(address, end, '49 89 CA 0F 05', 0x10, SEARCH_DOWN)

                if address == BADADDR or address >= end:
                    break

                number = None

                if idc.get_wide_byte(address - 0x7) == 0x48 and \
                   idc.get_wide_byte(address - 0x6) == 0xC7 and \
                   idc.get_wide_byte(address - 0x5) == 0xC0:
                    number = idc.get_wide_dword(address - 0x4)

                elif idc.get_wide_byte(address - 0x5) == 0xB8:
                    number = idc.get_wide_dword(address - 0x4)

                if number is not None and number < len(PS5_SYSCALLS):
                    idc.set_cmt(address + 0x3, 'sys_' + PS5_SYSCALLS[number], False)
                    found += 1

                address += 0x5

            log('Syscalls         %i commented' % found)

        except:
            pass


    # --------------------------------------------------------------------------------------------------------
    # Error Code Enumerator
    #
    # PS5 error codes run 0x80020000 .. 0x8A8E0014, so the PS4 loader's
    # 80xxxxxx pattern is too narrow -- match the whole 0x8_______ space and
    # let membership in the enum decide.
    if code is not None:
        try:
            log('Processing Error Codes...')

            values = set()
            tid    = BADADDR

            try:
                idc.import_type(-1, 'PS5_ERROR_CODES')
            except:
                pass

            # IDA 9.x -- enums live in the type library
            try:
                import ida_typeinf

                tid = ida_typeinf.get_named_type_tid('PS5_ERROR_CODES')

                tif = ida_typeinf.tinfo_t()
                if tif.get_named_type(None, 'PS5_ERROR_CODES'):
                    details = ida_typeinf.enum_type_data_t()
                    if tif.get_enum_details(details):
                        values = set(member.value & 0xFFFFFFFF for member in details)
            except:
                pass

            # IDA 7.x / 8.x -- the old standalone enum API
            if tid in (BADADDR, -1, None) or not values:
                try:
                    member = idaapi.get_enum_member_by_name('SCE_KERNEL_ERROR_EPERM')
                    tid    = idaapi.get_enum_member_enum(member)
                except:
                    pass

            if tid not in (BADADDR, -1, None):

                def is_error(errno):
                    if values:
                        return errno in values
                    try:
                        return idaapi.get_enum_member(tid, errno, -1, 0) != BADADDR
                    except:
                        return False

                address = code.start_ea
                applied = 0

                while True:
                    address = idaapi.find_text(address, 0, 0, '8[0-9a-fA-F]{7}h',
                                               SEARCH_DOWN | SEARCH_NEXT | SEARCH_REGEX)
                    if address == BADADDR:
                        break

                    # 0x8x is always at the top of the immediate
                    offset = idaapi.get_item_size(address) - 0x4
                    errno  = idaapi.get_dword(address + offset)

                    if is_error(errno):
                        try:
                            idc.op_enum(address, 1, tid, 0)
                            applied += 1
                        except:
                            pass

                    address = idaapi.next_head(address, BADADDR)

                log('Error Codes      %i operands typed (out of %i known codes)' % (applied, len(values)))

            else:
                log('Error Codes      PS5_ERROR_CODES not found -- is ps5_errno.til installed?')

        except:
            pass

    log('Done!')
    return 1

# PROGRAM END
