using static StealthModule.NativeMethods.NtDllDelegates;

namespace StealthModule
{
    internal static partial class NativeMethods
    {
        static bool ntdllInitialized;
        private static RtlInitUnicodeString rtlInitUnicodeString;
        private static RtlZeroMemory rtlZeroMemory;
        private static RtlGetVersion rtlGetVersion;
        private static RtlAddFunctionTable rtlAddFunctionTable;
        private static NtCreateSection ntCreateSection;
        private static NtMapViewOfSection ntMapViewOfSection;
        private static NtOpenFile ntOpenFile;
        private static NtProtectVirtualMemory ntProtectVirtualMemory;
        private static NtWriteVirtualMemory ntWriteVirtualMemory;
        private static NtAllocateVirtualMemory ntAllocateVirtualMemory;
        private static NtFreeVirtualMemory ntFreeVirtualMemory;
        private static NtQuerySystemInformation ntQuerySystemInformation;
        private static NtQueryInformationProcess ntQueryInformationProcess;
        private static LdrLoadDll ldrLoadDll;
        private static LdrUnloadDll ldrUnloadDll;
        private static LdrGetProcedureAddress ldrGetProcedureAddress;

        internal static void InitNtDLL()
        {
            if (ntdllInitialized)
                return;

            var kernel32 = new ExportResolver("ntdll.dll");
            kernel32.CacheAllExports(); // A bit overkill, but it is much more efficient.
            rtlInitUnicodeString = kernel32.GetExport<RtlInitUnicodeString>("RtlInitUnicodeString");
            rtlZeroMemory = kernel32.GetExport<RtlZeroMemory>("RtlZeroMemory");
            rtlGetVersion = kernel32.GetExport<RtlGetVersion>("RtlGetVersion");
            ntCreateSection = kernel32.GetExport<NtCreateSection>("NtCreateSection");
            ntMapViewOfSection = kernel32.GetExport<NtMapViewOfSection>("NtMapViewOfSection");
            ntOpenFile = kernel32.GetExport<NtOpenFile>("NtOpenFile");
            ntAllocateVirtualMemory = kernel32.GetExport<NtAllocateVirtualMemory>("NtAllocateVirtualMemory");
            ntFreeVirtualMemory = kernel32.GetExport<NtFreeVirtualMemory>("NtFreeVirtualMemory");
            ntWriteVirtualMemory = kernel32.GetExport<NtWriteVirtualMemory>("NtWriteVirtualMemory");
            ntProtectVirtualMemory = kernel32.GetExport<NtProtectVirtualMemory>("NtProtectVirtualMemory");
            ntQuerySystemInformation = kernel32.GetExport<NtQuerySystemInformation>("NtQuerySystemInformation");
            ntQueryInformationProcess = kernel32.GetExport<NtQueryInformationProcess>("NtQueryInformationProcess");
            ldrLoadDll = kernel32.GetExport<LdrLoadDll>("LdrLoadDll");
            ldrUnloadDll = kernel32.GetExport<LdrUnloadDll>("LdrUnloadDll");
            ldrGetProcedureAddress = kernel32.GetExport<LdrGetProcedureAddress>("LdrGetProcedureAddress");

            // Functions that only exist on x64
            if (Pointer.Is64Bit)
                rtlAddFunctionTable = kernel32.GetExport<RtlAddFunctionTable>("RtlAddFunctionTable");

            ntdllInitialized = true;
        }
    }
}
