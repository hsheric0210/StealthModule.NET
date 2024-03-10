using static StealthModule.NativeMethods.Kernel32Delegates;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        static bool kernel32Initialized;
        private static LoadLibrary loadLibrary;
        private static FreeLibrary freeLibrary;
        private static VirtualAlloc virtualAlloc;
        private static VirtualFree virtualFree;
        private static VirtualProtect virtualProtect;
        private static GetNativeSystemInfo getNativeSystemInfo;
        private static GetProcAddress getProcAddress;

        internal static void InitKernel32()
        {
            if (kernel32Initialized)
                return;

            var kernel32 = new ExportResolver("kernel32.dll");
            kernel32.CacheAllExports(); // A bit overkill, but it is much more efficient.
            loadLibrary = kernel32.GetExport<LoadLibrary>("LoadLibraryA");
            freeLibrary = kernel32.GetExport<FreeLibrary>("FreeLibrary");
            virtualAlloc = kernel32.GetExport<VirtualAlloc>("VirtualAlloc");
            virtualFree = kernel32.GetExport<VirtualFree>("VirtualFree");
            virtualProtect = kernel32.GetExport<VirtualProtect>("VirtualProtect");
            getNativeSystemInfo = kernel32.GetExport<GetNativeSystemInfo>("GetNativeSystemInfo");
            getProcAddress = kernel32.GetExport<GetProcAddress>("GetProcAddress");
            kernel32Initialized = true;
        }
    }
}
