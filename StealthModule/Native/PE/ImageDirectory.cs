using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace StealthModule.Native.PE
{
    #region Structs

    /// <summary>
    /// IMAGE_EXPORT_DIRECTORY
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageExportDirectory
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
    /// IMAGE_BASE_RELOCATION
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageBaseRelocation
    {
        public uint VirtualAdress;
        public uint SizeOfBlock;
    }

    /// <summary>
    /// IMAGE_DATA_DIRECTORY
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageDataDirectory
    {
        public uint VirtualAddress;
        public uint Size;
    }

    /// <summary>
    /// IMAGE_DELAYLOAD_DESCRIPTOR
    /// </summary>
    /// <remarks>
    /// available @ winnt.h
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageDelayImportDescriptor
    {
        public uint AllAttributes;
        public uint DllNameRVA;
        public uint ModuleHandleRVA;
        public uint ImportAddressTableRVA;
        public uint ImportNameTableRVA;
        public uint BoundImportAddressTableRVA;
        public uint UnloadInformationTableRVA;
        public uint TimeDateStamp;
    }

    /// <summary>
    /// IMAGE_IMPORT_DESCRIPTOR
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageImportDescriptor
    {
        public uint OriginalFirstThunk;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint FirstThunk;
    }

    /// <summary>
    /// IMAGE_TLS_DIRECTORY
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ImageTlsDirectory
    {
        public IntPtr StartAddressOfRawData;
        public IntPtr EndAddressOfRawData;
        public IntPtr AddressOfIndex;
        public IntPtr AddressOfCallBacks;
        public IntPtr SizeOfZeroFill;
        public uint Characteristics;
    }

    #endregion

    #region Enums

    public enum BasedRelocationType
    {
        IMAGE_REL_BASED_ABSOLUTE = 0,
        IMAGE_REL_BASED_HIGH = 1,
        IMAGE_REL_BASED_LOW = 2,
        IMAGE_REL_BASED_HIGHLOW = 3,
        IMAGE_REL_BASED_HIGHADJ = 4,
        IMAGE_REL_BASED_MIPS_JMPADDR = 5,
        IMAGE_REL_BASED_MIPS_JMPADDR16 = 9,
        IMAGE_REL_BASED_IA64_IMM64 = 9,
        IMAGE_REL_BASED_DIR64 = 10
    }

    #endregion
}
