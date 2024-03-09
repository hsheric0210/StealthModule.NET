﻿using System;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        private delegate IntPtr DLoadLibrary(IntPtr lpFileName);
        private delegate bool DFreeLibrary(IntPtr hModule);
        private delegate IntPtr DVirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
        private delegate bool DVirtualFree(IntPtr lpAddress, IntPtr dwSize, AllocationType dwFreeType);
        private delegate bool DVirtualProtect(IntPtr lpAddress, IntPtr dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);
        private delegate void DGetNativeSystemInfo(out SystemInfo lpSystemInfo);
        private delegate IntPtr DGetProcAddress(IntPtr hModule, IntPtr procName);

        static bool kernel32Initialized;
        private static DLoadLibrary loadLibrary;
        private static DFreeLibrary freeLibrary;
        private static DVirtualAlloc virtualAlloc;
        private static DVirtualFree virtualFree;
        private static DVirtualProtect virtualProtect;
        private static DGetNativeSystemInfo getNativeSystemInfo;
        private static DGetProcAddress getProcAddress;

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
            loadLibrary = (DLoadLibrary)kernel32.GetExport("LoadLibraryA", typeof(DLoadLibrary));
            freeLibrary = (DFreeLibrary)kernel32.GetExport("FreeLibrary", typeof(DFreeLibrary));
            virtualAlloc = (DVirtualAlloc)kernel32.GetExport("VirtualAlloc", typeof(DVirtualAlloc));
            virtualFree = (DVirtualFree)kernel32.GetExport("VirtualFree", typeof(DVirtualFree));
            virtualProtect = (DVirtualProtect)kernel32.GetExport("VirtualProtect", typeof(DVirtualProtect));
            getNativeSystemInfo = (DGetNativeSystemInfo)kernel32.GetExport("GetNativeSystemInfo", typeof(DGetNativeSystemInfo));
            getProcAddress = (DGetProcAddress)kernel32.GetExport("GetProcAddress", typeof(DGetProcAddress));
            kernel32Initialized = true;
        }
    }
}