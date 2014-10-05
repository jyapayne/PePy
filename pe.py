import os
import struct

struct_symbols = {1:'B',#byte
                  2:'H',#word
                  4:'L',#long word
                  8:'Q' #double long word
                }
endian_symbols = {'little':'<',
                  'big':'>'}

name_dictionary = {'PEHeader_Machine': {
                                0:'IMAGE_FILE_MACHINE_UNKNOWN',
                                0x014c:'IMAGE_FILE_MACHINE_I386',
                                0x0162:'IMAGE_FILE_MACHINE_R3000',
                                0x0166:'IMAGE_FILE_MACHINE_R4000',
                                0x0168:'IMAGE_FILE_MACHINE_R10000',
                                0x0169:'IMAGE_FILE_MACHINE_WCEMIPSV2',
                                0x0184:'IMAGE_FILE_MACHINE_ALPHA',
                                0x01a2:'IMAGE_FILE_MACHINE_SH3',
                                0x01a3:'IMAGE_FILE_MACHINE_SH3DSP',
                                0x01a4:'IMAGE_FILE_MACHINE_SH3E',
                                0x01a6:'IMAGE_FILE_MACHINE_SH4',
                                0x01a8:'IMAGE_FILE_MACHINE_SH5',
                                0x01c0:'IMAGE_FILE_MACHINE_ARM',
                                0x01c2:'IMAGE_FILE_MACHINE_THUMB',
                                0x01c4:'IMAGE_FILE_MACHINE_ARMNT',
                                0x01d3:'IMAGE_FILE_MACHINE_AM33',
                                0x01f0:'IMAGE_FILE_MACHINE_POWERPC',
                                0x01f1:'IMAGE_FILE_MACHINE_POWERPCFP',
                                0x0200:'IMAGE_FILE_MACHINE_IA64',
                                0x0266:'IMAGE_FILE_MACHINE_MIPS16',
                                0x0284:'IMAGE_FILE_MACHINE_ALPHA64',
                                0x0284:'IMAGE_FILE_MACHINE_AXP64', # same
                                0x0366:'IMAGE_FILE_MACHINE_MIPSFPU',
                                0x0466:'IMAGE_FILE_MACHINE_MIPSFPU16',
                                0x0520:'IMAGE_FILE_MACHINE_TRICORE',
                                0x0cef:'IMAGE_FILE_MACHINE_CEF',
                                0x0ebc:'IMAGE_FILE_MACHINE_EBC',
                                0x8664:'IMAGE_FILE_MACHINE_AMD64',
                                0x9041:'IMAGE_FILE_MACHINE_M32R',
                                0xc0ee:'IMAGE_FILE_MACHINE_CEE'
                      },

                     'PEHeader_Characteristics':{
                                0x0001:'IMAGE_FILE_RELOCS_STRIPPED',
                                0x0002:'IMAGE_FILE_EXECUTABLE_IMAGE',
                                0x0004:'IMAGE_FILE_LINE_NUMS_STRIPPED',
                                0x0008:'IMAGE_FILE_LOCAL_SYMS_STRIPPED',
                                0x0010:'IMAGE_FILE_AGGRESIVE_WS_TRIM',
                                0x0020:'IMAGE_FILE_LARGE_ADDRESS_AWARE',
                                0x0040:'IMAGE_FILE_16BIT_MACHINE',
                                0x0080:'IMAGE_FILE_BYTES_REVERSED_LO',
                                0x0100:'IMAGE_FILE_32BIT_MACHINE',
                                0x0200:'IMAGE_FILE_DEBUG_STRIPPED',
                                0x0400:'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP',
                                0x0800:'IMAGE_FILE_NET_RUN_FROM_SWAP',
                                0x1000:'IMAGE_FILE_SYSTEM',
                                0x2000:'IMAGE_FILE_DLL',
                                0x4000:'IMAGE_FILE_UP_SYSTEM_ONLY',
                                0x8000:'IMAGE_FILE_BYTES_REVERSED_HI'
                     },
                     'OptionalHeader_Subsystem':{
                                0:'IMAGE_SUBSYSTEM_UNKNOWN',
                                1:'IMAGE_SUBSYSTEM_NATIVE',
                                2:'IMAGE_SUBSYSTEM_WINDOWS_GUI',
                                3:'IMAGE_SUBSYSTEM_WINDOWS_CUI',
                                5:'IMAGE_SUBSYSTEM_OS2_CUI',
                                7:'IMAGE_SUBSYSTEM_POSIX_CUI',
                                8:'IMAGE_SUBSYSTEM_NATIVE_WINDOWS',
                                9:'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI',
                                10:'IMAGE_SUBSYSTEM_EFI_APPLICATION',
                                11:'IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER',
                                12:'IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER',
                                13:'IMAGE_SUBSYSTEM_EFI_ROM',
                                14:'IMAGE_SUBSYSTEM_XBOX',
                                16:'IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION'
                     },
                    'OptionalHeader_DLL_Characteristics':{
                                0x0001:'IMAGE_LIBRARY_PROCESS_INIT', # reserved
                                0x0002:'IMAGE_LIBRARY_PROCESS_TERM', # reserved
                                0x0004:'IMAGE_LIBRARY_THREAD_INIT', # reserved
                                0x0008:'IMAGE_LIBRARY_THREAD_TERM', # reserved
                                0x0020:'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA',
                                0x0040:'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE',
                                0x0080:'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY',
                                0x0100:'IMAGE_DLLCHARACTERISTICS_NX_COMPAT',
                                0x0200:'IMAGE_DLLCHARACTERISTICS_NO_ISOLATION',
                                0x0400:'IMAGE_DLLCHARACTERISTICS_NO_SEH',
                                0x0800:'IMAGE_DLLCHARACTERISTICS_NO_BIND',
                                0x1000:'IMAGE_DLLCHARACTERISTICS_APPCONTAINER',
                                0x2000:'IMAGE_DLLCHARACTERISTICS_WDM_DRIVER',
                                0x4000:'IMAGE_DLLCHARACTERISTICS_GUARD_CF',
                                0x8000:'IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE'
                     },

                    'SectionHeader_Characteristics':{

                                0x00000000:'IMAGE_SCN_TYPE_REG', # reserved
                                0x00000001:'IMAGE_SCN_TYPE_DSECT', # reserved
                                0x00000002:'IMAGE_SCN_TYPE_NOLOAD', # reserved
                                0x00000004:'IMAGE_SCN_TYPE_GROUP', # reserved
                                0x00000008:'IMAGE_SCN_TYPE_NO_PAD', # reserved
                                0x00000010:'IMAGE_SCN_TYPE_COPY', # reserved

                                0x00000020:'IMAGE_SCN_CNT_CODE',
                                0x00000040:'IMAGE_SCN_CNT_INITIALIZED_DATA',
                                0x00000080:'IMAGE_SCN_CNT_UNINITIALIZED_DATA',

                                0x00000100:'IMAGE_SCN_LNK_OTHER',
                                0x00000200:'IMAGE_SCN_LNK_INFO',
                                0x00000400:'IMAGE_SCN_LNK_OVER', # reserved
                                0x00000800:'IMAGE_SCN_LNK_REMOVE',
                                0x00001000:'IMAGE_SCN_LNK_COMDAT',

                                0x00004000:'IMAGE_SCN_MEM_PROTECTED', # obsolete
                                0x00004000:'IMAGE_SCN_NO_DEFER_SPEC_EXC',
                                0x00008000:'IMAGE_SCN_GPREL',
                                0x00008000:'IMAGE_SCN_MEM_FARDATA',
                                0x00010000:'IMAGE_SCN_MEM_SYSHEAP', # obsolete
                                0x00020000:'IMAGE_SCN_MEM_PURGEABLE',
                                0x00020000:'IMAGE_SCN_MEM_16BIT',
                                0x00040000:'IMAGE_SCN_MEM_LOCKED',
                                0x00080000:'IMAGE_SCN_MEM_PRELOAD',

                                0x00100000:'IMAGE_SCN_ALIGN_1BYTES',
                                0x00200000:'IMAGE_SCN_ALIGN_2BYTES',
                                0x00300000:'IMAGE_SCN_ALIGN_4BYTES',
                                0x00400000:'IMAGE_SCN_ALIGN_8BYTES',
                                0x00500000:'IMAGE_SCN_ALIGN_16BYTES', # default alignment
                                0x00600000:'IMAGE_SCN_ALIGN_32BYTES',
                                0x00700000:'IMAGE_SCN_ALIGN_64BYTES',
                                0x00800000:'IMAGE_SCN_ALIGN_128BYTES',
                                0x00900000:'IMAGE_SCN_ALIGN_256BYTES',
                                0x00A00000:'IMAGE_SCN_ALIGN_512BYTES',
                                0x00B00000:'IMAGE_SCN_ALIGN_1024BYTES',
                                0x00C00000:'IMAGE_SCN_ALIGN_2048BYTES',
                                0x00D00000:'IMAGE_SCN_ALIGN_4096BYTES',
                                0x00E00000:'IMAGE_SCN_ALIGN_8192BYTES',
                                0x00F00000:'IMAGE_SCN_ALIGN_MASK',

                                0x01000000:'IMAGE_SCN_LNK_NRELOC_OVFL',
                                0x02000000:'IMAGE_SCN_MEM_DISCARDABLE',
                                0x04000000:'IMAGE_SCN_MEM_NOT_CACHED',
                                0x08000000:'IMAGE_SCN_MEM_NOT_PAGED',
                                0x10000000:'IMAGE_SCN_MEM_SHARED',
                                0x20000000:'IMAGE_SCN_MEM_EXECUTE',
                                0x40000000:'IMAGE_SCN_MEM_READ',
                                0x80000000L:'IMAGE_SCN_MEM_WRITE',

                    },
}

_32BIT_PLUS_MAGIC = 0x20b
_32BIT_MAGIC = 0x10b
_ROM_MAGIC = 0x107

def read_from_name_dict(obj, field_name):
    dict_field = '{}_{}'.format(obj.__class__.__name__, field_name)
    return name_dictionary.get(dict_field, {})

def test_bit(value, index):
    mask = 1 << index
    return (value & mask)

class PEFormatError(Exception):
    pass

class Printable(object):
    def _attrs(self):
        a = []
        for attr in dir(self):
            if not attr.startswith('_') and not callable(getattr(self, attr)):
                a.append(attr)
        return a

    def _dict_items(self):
        for a in reversed(self._attrs()):
            yield a, getattr(self,a)

    def _dict_string(self):
        vals = []
        for key, val in self._dict_items():
            try:
                vals.append(u'{}={}'.format(key, val))
            except UnicodeDecodeError:
                vals.append(u'{}=<not printable>'.format(key))
        return u', '.join(vals)

    def __repr__(self):
        return unicode(self)

    def __str__(self):
        return unicode(self).encode('utf-8')

    def __unicode__(self):
        return u'{} [{}]'.format(self.__class__.__name__, self._dict_string())


class Structure(Printable):

    _fields = {}

    def __init__(self, offset=0, size=0, value=None, data=None, absolute_offset=0,
                 name='', friendly_name='', *args, **kwargs):
        super(Structure, self).__init__()
        self.offset = offset
        self.size = size
        self.value = value
        self.data = data
        self.name = name
        self.friendly_name = friendly_name
        self.absolute_offset = absolute_offset

        for k, v in kwargs.items():
            setattr(self, k, v)

    def process_field(self, pe_file, field_name, field_info):

        if hasattr(self, 'process_'+field_name) and callable(getattr(self, 'process_'+field_name)):
            getattr(self, 'process_'+field_name)(pe_file, field_name, field_info)
        else:
            absolute_offset = field_info['offset'] + self.offset
            size = field_info['size']
            self.size += size
            int_value, data = pe_file.read_bytes(absolute_offset, size)
            field_name_dict = read_from_name_dict(self, field_name)
            name = field_name_dict.get(int_value, '')
            friendly_name = name.replace('_', ' ').capitalize()

            setattr(self, field_name, Structure(offset=field_info['offset'],
                                                size=size,
                                                value=int_value, data=data,
                                                absolute_offset=absolute_offset,
                                                name=name, friendly_name=friendly_name))


    def process_Characteristics(self, pe_file, field_name, field_info):
        absolute_offset = field_info['offset'] + self.offset
        size = field_info['size']
        self.size += size
        int_value, data = pe_file.read_bytes(absolute_offset, size)
        field_name_dict = read_from_name_dict(self, field_name)

        bit_length = len(bin(int_value))-2

        characteristics = {}
        for i in xrange(bit_length):
            set_bit = test_bit(int_value, i)
            if set_bit != 0:
                characteristics[field_name_dict[set_bit]] = set_bit


        setattr(self, field_name, Structure(offset=field_info['offset'],
                                            size=size,
                                            value=int_value, data=data,
                                            absolute_offset=absolute_offset,
                                            values=characteristics,
                                            ))

    @classmethod
    def parse_from_data(cls, pe_file, **cls_args):
        """Parses the Structure from the file data."""
        self = cls(**cls_args)
        for field_name, field_info in self._fields.items():
            self.process_field(pe_file, field_name, field_info)
        return self



class DOSHeader(Structure):
    """The dos header of the PE file"""

    _fields = {'Signature':{'offset':0,
                           'size':2},
              'PEHeaderOffset':{'offset':0x3c,
                                'size':4}
              }




class PEHeader(Structure):
    """PE signature plus the COFF header"""

    _fields = {'Signature':{'offset':0,
                           'size':4},
              'Machine':{'offset':4,
                         'size':2},
              'NumberOfSections':{'offset':6,
                                  'size':2},
              'TimeDateStamp':{'offset':8,
                               'size':4},
              'PointerToSymbolTable':{'offset':12,
                                      'size':4},
              'NumberOfSymbols':{'offset':16,
                                 'size':4},
              'SizeOfOptionalHeader':{'offset':20,
                                      'size':2},
              'Characteristics':{'offset':22,
                                 'size':2}
              }


class OptionalHeader(Structure):
    _fields_32_plus = {'Magic':{'offset':0,
                        'size':2},
              'MajorLinkerVersion':{'offset':2,
                                    'size':1},
              'MinorLinkerVersion':{'offset':3,
                                    'size':1},
              'SizeOfCode':{'offset':4,
                            'size':4},
              'SizeOfInitializedData':{'offset':8,
                                       'size':4},
              'SizeOfUninitializedData':{'offset':12,
                                         'size':4},
              'AddressOfEntryPoint':{'offset':16,
                                     'size':4},
              'BaseOfCode':{'offset':20,
                            'size':4},
              'ImageBase':{'offset':24,
                            'size':8},
              'SectionAlignment':{'offset':32,
                                  'size':4},
              'FileAlignment':{'offset':36,
                                'size':4},
              'MajorOperatingSystemVersion':{'offset':40,
                                             'size':2},
              'MinorOperatingSystemVersion':{'offset':42,
                                             'size':2},
              'MajorImageVersion':{'offset':44,
                                   'size':2},
              'MinorImageVersion':{'offset':46,
                                   'size':2},
              'MajorSubsystemVersion':{'offset':48,
                                       'size':2},
              'MinorSubsystemVersion':{'offset':50,
                                       'size':2},
              'Reserved':{'offset':52,
                          'size':4},
              'SizeOfImage':{'offset':56,
                             'size':4},
              'SizeOfHeaders':{'offset':60,
                               'size':4},
              'SizeOfHeaders':{'offset':60,
                               'size':4},
              'CheckSum': {'offset': 64,
                            'size':4},
              'Subsystem':{'offset':68,
                               'size':2},
              'DLL_Characteristics':{'offset':70,
                               'size':2},
              'SizeOfStackReserve':{'offset':72,
                               'size':8},
              'SizeOfStackCommit':{'offset':80,
                               'size':8},
              'SizeOfHeapReserve':{'offset':88,
                               'size':8},
              'SizeOfHeapCommit':{'offset':96,
                               'size':8},
              'LoaderFlags':{'offset':104,
                               'size':4},
              'NumberOfRvaAndSizes':{'offset':108,
                               'size':4},
              'ExportTableAddress':{'offset':112,
                               'size':4},
              'ExportTableSize':{'offset':116,
                               'size':4},
              'ImportTableAddress':{'offset':120,
                               'size':4},
              'ImportTableSize':{'offset':124,
                               'size':4},
              'ResourceTableAddress':{'offset':128,
                               'size':4},
              'ResourceTableSize':{'offset':132,
                               'size':4},
              'ExceptionTableAddress':{'offset':136,
                               'size':4},
              'ExceptionTableSize':{'offset':140,
                               'size':4},
              'CertificateTableAddress':{'offset':144,
                               'size':4},
              'CertificateTableSize':{'offset':148,
                               'size':4},
              'BaseRelocationTableAddress':{'offset':152,
                               'size':4},
              'BaseRelocationTableSize':{'offset':156,
                               'size':4},
              'DebugAddress':{'offset':160,
                               'size':4},
              'DebugSize':{'offset':164,
                               'size':4},
              'ArchitectureAddress':{'offset':168,
                               'size':4},
              'ArchitectureSize':{'offset':172,
                               'size':4},
              'GlobalPtrAddress':{'offset':176,
                               'size':8},
              'GlobalPtrSize':{'offset':184,
                               'size':0},
              'ThreadLocalStorageTableAddress':{'offset':184,
                               'size':4},
              'ThreadLocalStorageTableSize':{'offset':188,
                               'size':4},
              'LoadConfigTableAddress':{'offset':192,
                               'size':4},
              'LoadConfigTableSize':{'offset':196,
                               'size':4},
              'BoundImportAddress':{'offset':200,
                               'size':4},
              'BoundImportSize':{'offset':204,
                               'size':4},
              'ImportAddressTableAddress':{'offset':208,
                               'size':4},
              'ImportAddressTableSize':{'offset':212,
                               'size':4},
              'DelayImportDescriptorAddress':{'offset':216,
                               'size':4},
              'DelayImportDescriptorSize':{'offset':220,
                               'size':4},
              'COMRuntimeHeaderAddress':{'offset':224,
                               'size':4},
              'COMRuntimeHeaderSize':{'offset':228,
                               'size':4},
              'Reserved2':{'offset':232,
                               'size':8}

            }

    _fields_32 = {'Magic':{'offset':0,
                        'size':2},
              'MajorLinkerVersion':{'offset':2,
                                    'size':1},
              'MinorLinkerVersion':{'offset':3,
                                    'size':1},
              'SizeOfCode':{'offset':4,
                            'size':4},
              'SizeOfInitializedData':{'offset':8,
                                       'size':4},
              'SizeOfUninitializedData':{'offset':12,
                                         'size':4},
              'AddressOfEntryPoint':{'offset':16,
                                     'size':4},
              'BaseOfCode':{'offset':20,
                            'size':4},
              'BaseOfData':{'offset':24,
                            'size':4},
              'ImageBase':{'offset':28,
                            'size':4},
              'SectionAlignment':{'offset':32,
                                  'size':4},
              'FileAlignment':{'offset':36,
                                'size':4},
              'MajorOperatingSystemVersion':{'offset':40,
                                             'size':2},
              'MinorOperatingSystemVersion':{'offset':42,
                                             'size':2},
              'MajorImageVersion':{'offset':44,
                                   'size':2},
              'MinorImageVersion':{'offset':46,
                                   'size':2},
              'MajorSubsystemVersion':{'offset':48,
                                       'size':2},
              'MinorSubsystemVersion':{'offset':50,
                                       'size':2},
              'Reserved':{'offset':52,
                          'size':4},
              'SizeOfImage':{'offset':56,
                             'size':4},
              'SizeOfHeaders':{'offset':60,
                               'size':4},
              'SizeOfHeaders':{'offset':60,
                               'size':4},
              'CheckSum': {'offset': 64,
                            'size':4},
              'Subsystem':{'offset':68,
                               'size':2},
              'DLL_Characteristics':{'offset':70,
                               'size':2},
              'SizeOfStackReserve':{'offset':72,
                               'size':4},
              'SizeOfStackCommit':{'offset':76,
                               'size':4},
              'SizeOfHeapReserve':{'offset':80,
                               'size':4},
              'SizeOfHeapCommit':{'offset':84,
                               'size':4},
              'LoaderFlags':{'offset':88,
                               'size':4},
              'NumberOfRvaAndSizes':{'offset':92,
                               'size':4},
              'ExportTableAddress':{'offset':96,
                               'size':4},
              'ExportTableSize':{'offset':100,
                               'size':4},
              'ImportTableAddress':{'offset':104,
                               'size':4},
              'ImportTableSize':{'offset':108,
                               'size':4},
              'ResourceTableAddress':{'offset':112,
                               'size':4},
              'ResourceTableSize':{'offset':116,
                               'size':4},
              'ExceptionTableAddress':{'offset':120,
                               'size':4},
              'ExceptionTableSize':{'offset':124,
                               'size':4},
              'CertificateTableAddress':{'offset':128,
                               'size':4},
              'CertificateTableSize':{'offset':132,
                               'size':4},
              'BaseRelocationTableAddress':{'offset':136,
                               'size':4},
              'BaseRelocationTableSize':{'offset':140,
                               'size':4},
              'DebugAddress':{'offset':144,
                               'size':4},
              'DebugSize':{'offset':148,
                               'size':4},
              'ArchitectureAddress':{'offset':152,
                               'size':4},
              'ArchitectureSize':{'offset':156,
                               'size':4},
              'GlobalPtrAddress':{'offset':160,
                               'size':8},
              'GlobalPtrSize':{'offset':168,
                               'size':0},
              'ThreadLocalStorageTableAddress':{'offset':168,
                               'size':4},
              'ThreadLocalStorageTableSize':{'offset':172,
                               'size':4},
              'LoadConfigTableAddress':{'offset':176,
                               'size':4},
              'LoadConfigTableSize':{'offset':180,
                               'size':4},
              'BoundImportAddress':{'offset':184,
                               'size':4},
              'BoundImportSize':{'offset':188,
                               'size':4},
              'ImportAddressTableAddress':{'offset':192,
                               'size':4},
              'ImportAddressTableSize':{'offset':196,
                               'size':4},
              'DelayImportDescriptorAddress':{'offset':200,
                               'size':4},
              'DelayImportDescriptorSize':{'offset':204,
                               'size':4},
              'COMRuntimeHeaderAddress':{'offset':208,
                               'size':4},
              'COMRuntimeHeaderSize':{'offset':212,
                               'size':4},
              'Reserved2':{'offset':216,
                               'size':8},


              }

    def process_DLL_Characteristics(self, pe_file, field_name, field_info):
        self.process_Characteristics(pe_file, field_name, field_info)


    @classmethod
    def parse_from_data(cls, pe_file, **cls_args):
        """Parses the Structure from the file data."""
        self = cls(**cls_args)
        magic, _ = int_value, data = pe_file.read_bytes(self.offset, 2)

        if magic == _32BIT_MAGIC:
            self._fields = self._fields_32
        elif magic == _32BIT_PLUS_MAGIC:
            self._fields = self._fields_32_plus
        else:
            raise PEFormatError('Magic for Optional Header is invalid.')

        for field_name, field_info in self._fields.items():
            self.process_field(pe_file, field_name, field_info)

        return self

class SectionHeader(Structure):
    """Section Header. Each section header is a row in the section table"""

    _fields = {'Name':{'offset':0,
                           'size':8},
              'VirtualSize':{'offset':8,
                         'size':4},
              'VirtualAddress':{'offset':12,
                                  'size':4},
              'SizeOfRawData':{'offset':16,
                               'size':4},
              'PointerToRawData':{'offset':20,
                                      'size':4},
              'PointerToRelocations':{'offset':24,
                                 'size':4},
              'PointerToLineNumbers':{'offset':28,
                                      'size':4},
              'NumberOfRelocations':{'offset':32,
                                 'size':2},
              'NumberOfLineNumbers':{'offset':34,
                                 'size':2},
              'Characteristics':{'offset':36,
                                 'size':4}
              }



class PEFile(Printable):
    """Reads a portable exe file in either big or little endian."""

    signature = 'MZ'
    dos_header = None

    def __init__(self, file_path, endian='little'):
        self.file_path = os.path.abspath(os.path.expanduser(file_path))

        self.endian = endian
        if not self.is_PEFile():
            raise PEFormatError('File is not a proper portable executable formatted file!')

        self.pe_file_data = open(self.file_path,'rb').read()

        self.dos_header = DOSHeader.parse_from_data(self)
        self.pe_header = PEHeader.parse_from_data(self, offset=self.dos_header.PEHeaderOffset.value)
        self.optional_header = OptionalHeader.parse_from_data(self, offset=self.pe_header.size+self.pe_header.offset)

        number_of_sections = self.pe_header.NumberOfSections.value
        section_size = 40
        section_offset = self.pe_header.size+self.pe_header.offset+self.pe_header.SizeOfOptionalHeader.value
        self.section_headers = []

        for section_number in xrange(number_of_sections):
            section = SectionHeader.parse_from_data(self, offset=section_offset)
            section_offset += section_size
            self.section_headers.append(section)


    def is_PEFile(self):
        """Checks if the file is a proper PE file"""
        signature = None
        try:
            with open(self.file_path,'rb') as f:
                signature = f.read(2)
        except IOError as e:
            raise e
        finally:
            return signature == self.signature

    def read_bytes(self, offset, number_of_bytes, endian=None):
        """Returns a tuple of the data value and string representation.
        (value, string)
        """

        if number_of_bytes > 0:

            if endian:
                endian = endian_symbols[endian]
            else:
                endian = endian_symbols[self.endian]

            data = self.pe_file_data[offset:offset+number_of_bytes]

            return struct.unpack(endian+struct_symbols[number_of_bytes], data)[0], data
        else:
            return 0,''
