using static StealthModule.NativeMethods.NtDllDelegates;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        static bool ntdllInitialized;
        private static RtlInitUnicodeString rtlInitUnicodeString;
        private static RtlZeroMemory rtlZeroMemory;
        private static NtCreateSection ntCreateSection;
        private static NtMapViewOfSection ntMapViewOfSection;
        private static NtOpenFile ntOpenFile;
        private static NtProtectVirtualMemory ntProtectVirtualMemory;
        private static NtWriteVirtualMemory ntWriteVirtualMemory;
        private static NtAllocateVirtualMemory ntAllocateVirtualMemory;
        private static NtFreeVirtualMemory ntFreeVirtualMemory;

        internal static void InitNtDll()
        {
            if (ntdllInitialized)
                return;

            var kernel32 = new ExportResolver("ntdll.dll");
            kernel32.CacheAllExports(); // A bit overkill, but it is much more efficient.
            rtlInitUnicodeString = kernel32.GetExport<RtlInitUnicodeString>("RtlInitUnicodeString");
            rtlZeroMemory = kernel32.GetExport<RtlZeroMemory>("RtlZeroMemory");
            ntCreateSection = kernel32.GetExport<NtCreateSection>("NtCreateSection");
            ntMapViewOfSection = kernel32.GetExport<NtMapViewOfSection>("NtMapViewOfSection");
            ntOpenFile = kernel32.GetExport<NtOpenFile>("NtOpenFile");
            ntAllocateVirtualMemory = kernel32.GetExport<NtAllocateVirtualMemory>("NtAllocateVirtualMemory");
            ntFreeVirtualMemory = kernel32.GetExport<NtFreeVirtualMemory>("NtFreeVirtualMemory");
            ntWriteVirtualMemory = kernel32.GetExport<NtWriteVirtualMemory>("NtWriteVirtualMemory");
            ntProtectVirtualMemory = kernel32.GetExport<NtProtectVirtualMemory>("NtProtectVirtualMemory");
            ntdllInitialized = true;
        }
    }
}
