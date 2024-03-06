using System;

namespace StealthModule
{
    internal partial class NativeMethods
    {

        // Equivalent to the IMAGE_FIRST_SECTION macro
        internal static Pointer IMAGE_FIRST_SECTION(Pointer pNTHeader, ushort ntheader_FileHeader_SizeOfOptionalHeader) => pNTHeader + Of.IMAGE_NT_HEADERS_OptionalHeader + ntheader_FileHeader_SizeOfOptionalHeader;

        // Equivalent to the IMAGE_FIRST_SECTION macro
        internal static int IMAGE_FIRST_SECTION(int lfanew, ushort ntheader_FileHeader_SizeOfOptionalHeader) => lfanew + Of.IMAGE_NT_HEADERS_OptionalHeader + ntheader_FileHeader_SizeOfOptionalHeader;

        // Equivalent to the IMAGE_ORDINAL32/64 macros
        internal static Pointer IMAGE_ORDINAL(Pointer ordinal) => (Pointer)(uint)((ulong)ordinal & 0xffff);

        // Equivalent to the IMAGE_SNAP_BY_ORDINAL32/64 macro
        internal static bool IMAGE_SNAP_BY_ORDINAL(Pointer ordinal) => IntPtr.Size == 8 ? ((long)ordinal < 0) : ((int)ordinal < 0);
    }
}
