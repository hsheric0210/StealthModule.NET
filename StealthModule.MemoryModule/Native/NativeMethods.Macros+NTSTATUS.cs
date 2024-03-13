using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule
{
    internal partial class NativeMethods
    {
        public static bool NT_SUCCESS(ulong value) => value <= 0x7FFFFFFF;
        public static bool NT_SUCCESS(NTSTATUS value) => NT_SUCCESS((ulong)value);

        public static bool NT_INFORMATION(ulong value) => value >= 0x40000000 && value <= 0x7FFFFFFF;
        public static bool NT_INFORMATION(NTSTATUS value) => NT_INFORMATION((ulong)value);

        public static bool NT_WARNING(ulong value) => value >= 0x80000000 && value <= 0xBFFFFFFF;
        public static bool NT_WARNING(NTSTATUS value) => NT_WARNING((ulong)value);

        public static bool NT_ERROR(ulong value) => value >= 0xC0000000 && value <= 0xFFFFFFFF;
        public static bool NT_ERROR(NTSTATUS value) => NT_ERROR((ulong)value);
    }
}
