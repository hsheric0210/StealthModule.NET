using System;
using static StealthModule.NativeMethods.Kernel32Delegates;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        internal static class Kernel32Delegates
        {
            internal delegate IntPtr LoadLibrary(IntPtr lpFileName);
            internal delegate bool FreeLibrary(IntPtr hModule);
            internal delegate IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
            internal delegate bool VirtualFree(IntPtr lpAddress, IntPtr dwSize, AllocationType dwFreeType);
            internal delegate bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);
            internal delegate void GetNativeSystemInfo(out SystemInfo lpSystemInfo);
            internal delegate IntPtr GetProcAddress(IntPtr hModule, IntPtr procName);
        }

        static bool kernel32Initialized;
        private static LoadLibrary loadLibrary;
        private static FreeLibrary freeLibrary;
        private static VirtualAlloc virtualAlloc;
        private static VirtualFree virtualFree;
        private static VirtualProtect virtualProtect;
        private static GetNativeSystemInfo getNativeSystemInfo;
        private static GetProcAddress getProcAddress;

        internal static Pointer LoadLibrary(Pointer lpFileName)
        {
            if (loadLibrary == null)
                InitKernel32();

            return loadLibrary(lpFileName);
        }

        internal static bool FreeLibrary(Pointer hModule)
        {
            if (freeLibrary == null)
                InitKernel32();

            return freeLibrary(hModule);
        }

        internal static Pointer VirtualAlloc(Pointer lpAddress, Pointer dwSize, AllocationType flAllocationType, MemoryProtection flProtect)
        {
            if (virtualAlloc == null)
                InitKernel32();

            return virtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
        }

        internal static bool VirtualFree(Pointer lpAddress, Pointer dwSize, AllocationType dwFreeType)
        {
            if (virtualFree == null)
                InitKernel32();

            return virtualFree(lpAddress, dwSize, dwFreeType);
        }

        internal static bool VirtualProtect(Pointer lpAddress, Pointer dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect)
        {
            if (virtualProtect == null)
                InitKernel32();

            return virtualProtect(lpAddress, dwSize, flNewProtect, out lpflOldProtect);
        }

        internal static void GetNativeSystemInfo(out SystemInfo lpSystemInfo)
        {
            if (getNativeSystemInfo == null)
                InitKernel32();

            getNativeSystemInfo(out lpSystemInfo);
        }

        internal static Pointer GetProcAddress(Pointer hModule, Pointer procName)
        {
            if (getProcAddress == null)
                InitKernel32();

            return getProcAddress(hModule, procName);
        }

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
