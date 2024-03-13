namespace StealthModule.Native.PE
{
    public static class NativeMagics
    {
        public const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ

        public const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE

        public const uint IMAGE_FILE_MACHINE_I386 = 0x014c;
        public const uint IMAGE_FILE_MACHINE_AMD64 = 0x8664;

        public const uint IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
        public const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;

        public const uint IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        public const uint IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;

        public const uint IMAGE_FILE_DLL = 0x2000;
    }

    public static class NativeOffsets
    {
        public const int IMAGE_NT_HEADERS_OptionalHeader = 0x18;
        public const int IMAGE_SECTION_HEADER_PhysicalAddress = 0x8;
        public const int IMAGE_IMPORT_BY_NAME_Name = 0x2;
    }

    public static class NativeOffsets32
    {
        public const int IMAGE_OPTIONAL_HEADER_ImageBase = 0x1C;
        public const int IMAGE_OPTIONAL_HEADER_ExportTable = 0x60;
    }

    public static class NativeOffsets64
    {
        public const int IMAGE_OPTIONAL_HEADER_ImageBase = 0x18;
        public const int IMAGE_OPTIONAL_HEADER_ExportTable = 0x70;
    }

    public static class NativeSizes
    {
        public const int IMAGE_SECTION_HEADER = 0x28;
        public const int IMAGE_BASE_RELOCATION = 0x8;
        public const int IMAGE_IMPORT_DESCRIPTOR = 0x14;
    }
}
