using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    /// <summary>
    /// IMAGE_DOS_HEADER
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageDosHeader
    {
        public ushort e_magic;    // Magic number
        public ushort e_cblp;     // Bytes on last page of file
        public ushort e_cp;       // Pages in file
        public ushort e_crlc;     // Relocations
        public ushort e_cparhdr;  // Size of header in paragraphs
        public ushort e_minalloc; // Minimum extra paragraphs needed
        public ushort e_maxalloc; // Maximum extra paragraphs needed
        public ushort e_ss;       // Initial (relative) SS value
        public ushort e_sp;       // Initial SP value
        public ushort e_csum;     // Checksum
        public ushort e_ip;       // Initial IP value
        public ushort e_cs;       // Initial (relative) CS value
        public ushort e_lfarlc;   // File address of relocation table
        public ushort e_ovno;     // Overlay number
        public ushort e_res1a, e_res1b, e_res1c, e_res1d; // Reserved words
        public ushort e_oemid;    // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo;  // OEM information; e_oemid specific
        public ushort e_res2a, e_res2b, e_res2c, e_res2d, e_res2e, e_res2f, e_res2g, e_res2h, e_res2i, e_res2j; // Reserved words
        public int e_lfanew;      // File address of new exe header
    }

    /// <summary>
    /// IMAGE_NT_HEADERS
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageNtHeaders
    {
        public uint Signature;
        public ImageFileHeader FileHeader;
        public ImageOptionalHeader OptionalHeader;
    }

    /// <summary>
    /// IMAGE_FILE_HEADER
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageFileHeader
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    /// <summary>
    /// IMAGE_OPTIONAL_HEADER
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageOptionalHeader
    {
        public MagicType Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBaseLong;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public SubSystemType Subsystem;
        public DllCharacteristicsType DllCharacteristics;
        public IntPtr SizeOfStackReserve;
        public IntPtr SizeOfStackCommit;
        public IntPtr SizeOfHeapReserve;
        public IntPtr SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public ImageDataDirectory ExportTable;
        public ImageDataDirectory ImportTable;
        public ImageDataDirectory ResourceTable;
        public ImageDataDirectory ExceptionTable;
        public ImageDataDirectory CertificateTable;
        public ImageDataDirectory BaseRelocationTable;
        public ImageDataDirectory Debug;
        public ImageDataDirectory Architecture;
        public ImageDataDirectory GlobalPtr;
        public ImageDataDirectory TLSTable;
        public ImageDataDirectory LoadConfigTable;
        public ImageDataDirectory BoundImport;
        public ImageDataDirectory IAT;
        public ImageDataDirectory DelayImportDescriptor;
        public ImageDataDirectory CLRRuntimeHeader;
        public ImageDataDirectory Reserved;
    }

    /// <summary>
    /// IMAGE_DATA_DIRECTORY
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageDataDirectory
    {
        public uint VirtualAddress;
        public uint Size;
    }

    /// <summary>
    /// IMAGE_SECTION_HEADER
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageSectionHeader
    {
        public ulong Name; //8 byte string
        public uint PhysicalAddress;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    /// <summary>
    /// IMAGE_BASE_RELOCATION
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageBaseRelocation
    {
        public uint VirtualAdress;
        public uint SizeOfBlock;
    }

    /// <summary>
    /// IMAGE_IMPORT_DESCRIPTOR
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageImportDescriptor
    {
        public uint OriginalFirstThunk;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint FirstThunk;
    }

    /// <summary>
    /// IMAGE_EXPORT_DIRECTORY
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageExportDirectory
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;     // RVA from base of image
        public uint AddressOfNames;         // RVA from base of image
        public uint AddressOfNameOrdinals;  // RVA from base of image
    }

    /// <summary>
    /// IMAGE_TLS_DIRECTORY
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ImageTlsDirectory
    {
        public IntPtr StartAddressOfRawData;
        public IntPtr EndAddressOfRawData;
        public IntPtr AddressOfIndex;
        public IntPtr AddressOfCallBacks;
        public IntPtr SizeOfZeroFill;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ApiSetNamespace
    {
        [FieldOffset(0x0C)]
        public int Count;

        [FieldOffset(0x10)]
        public int EntryOffset;
    }

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    public struct ApiSetNamespaceEntry
    {
        [FieldOffset(0x04)]
        public int NameOffset;

        [FieldOffset(0x08)]
        public int NameLength;

        [FieldOffset(0x10)]
        public int ValueOffset;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ApiSetValueEntry
    {
        [FieldOffset(0x0C)]
        public int ValueOffset;

        [FieldOffset(0x10)]
        public int ValueCount;
    }
}
