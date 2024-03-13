using System;
using System.Runtime.InteropServices;

/* Unmerged change from project 'StealthModule.MemoryModule (net8.0-windows)'
Before:
using StealthModule.MemoryModule.Native;
After:
using StealthModule;
using StealthModule.MemoryModule.Native;
*/

namespace StealthModule.Native.PE
{
    #region Structs

    /// <summary>
    /// IMAGE_DOS_HEADER
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageDosHeader
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
    public struct ImageNtHeaders
    {
        public uint Signature;
        public ImageFileHeader FileHeader;
        public ImageOptionalHeader OptionalHeader;
    }

    /// <summary>
    /// IMAGE_FILE_HEADER
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageFileHeader
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
    public struct ImageOptionalHeader
    {
        public NtOptionalHeaderMagic Magic;
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
    /// IMAGE_SECTION_HEADER
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageSectionHeader
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

    #endregion

    #region Enums

    public enum NtOptionalHeaderMagic : ushort
    {
        Header32Magic = 0x10b,
        Header64Magic = 0x20b
    }

    public enum SubSystemType : ushort
    {
        IMAGE_SUBSYSTEM_UNKNOWN = 0,
        IMAGE_SUBSYSTEM_NATIVE = 1,
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
        IMAGE_SUBSYSTEM_POSIX_CUI = 7,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
        IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
        IMAGE_SUBSYSTEM_EFI_ROM = 13,
        IMAGE_SUBSYSTEM_XBOX = 14
    }

    [Flags]
    public enum DllCharacteristicsType : ushort
    {
        RES_0 = 1 << 0,
        RES_1 = 1 << 1,
        RES_2 = 1 << 2,
        RES_3 = 1 << 3,
        IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 1 << 6,
        IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 1 << 7,
        IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 1 << 8,
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 1 << 9,
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 1 << 10,
        IMAGE_DLLCHARACTERISTICS_NO_BIND = 1 << 11,
        RES_4 = 1 << 12,
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 1 << 13,
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 1 << 15
    }

    #endregion
}
