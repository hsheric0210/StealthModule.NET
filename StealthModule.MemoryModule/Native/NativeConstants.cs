namespace StealthModule.MemoryModule.Native
{
    internal static class NativeMagics
    {
        internal const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
        internal const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE
        internal const uint IMAGE_FILE_MACHINE_I386 = 0x014c;
        internal const uint IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        internal const uint IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
        internal const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
        internal const uint IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        internal const uint IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        internal const uint IMAGE_FILE_DLL = 0x2000;
    }

    internal static class NativeOffsets
    {
        internal const int IMAGE_NT_HEADERS_OptionalHeader = 0x18;
        internal const int IMAGE_SECTION_HEADER_PhysicalAddress = 0x8;
        internal const int IMAGE_IMPORT_BY_NAME_Name = 0x2;
    }

    internal static class NativeOffsets32
    {
        internal const int IMAGE_OPTIONAL_HEADER_ImageBase = 0x1C;
        internal const int IMAGE_OPTIONAL_HEADER_ExportTable = 0x60;
    }

    internal static class NativeOffsets64
    {
        internal const int IMAGE_OPTIONAL_HEADER_ImageBase = 0x18;
        internal const int IMAGE_OPTIONAL_HEADER_ExportTable = 0x70;
    }

    internal static class NativeSizes
    {
        internal const int IMAGE_SECTION_HEADER = 0x28;
        internal const int IMAGE_BASE_RELOCATION = 0x8;
        internal const int IMAGE_IMPORT_DESCRIPTOR = 0x14;
    }
}
