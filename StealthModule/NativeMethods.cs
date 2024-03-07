﻿using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        private delegate IntPtr DLoadLibrary(IntPtr lpFileName);
        private delegate bool DFreeLibrary(IntPtr hModule);
        private delegate IntPtr DVirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
        private delegate bool DVirtualFree(IntPtr lpAddress, IntPtr dwSize, AllocationType dwFreeType);
        private delegate bool DVirtualProtect(IntPtr lpAddress, IntPtr dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);
        private delegate void DGetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);
        private delegate IntPtr DGetProcAddress(IntPtr hModule, IntPtr procName);

        static bool nativeInitialized;
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
                InitNatives();

            return loadLibrary(lpFileName);
        }

        internal static bool FreeLibrary(Pointer hModule)
        {
            if (freeLibrary == null)
                InitNatives();

            return freeLibrary(hModule);
        }

        internal static Pointer VirtualAlloc(Pointer lpAddress, Pointer dwSize, AllocationType flAllocationType, MemoryProtection flProtect)
        {
            if (virtualAlloc == null)
                InitNatives();

            return virtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
        }

        internal static bool VirtualFree(Pointer lpAddress, Pointer dwSize, AllocationType dwFreeType)
        {
            if (virtualFree == null)
                InitNatives();

            return virtualFree(lpAddress, dwSize, dwFreeType);
        }

        internal static bool VirtualProtect(Pointer lpAddress, Pointer dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect)
        {
            if (virtualProtect == null)
                InitNatives();

            return virtualProtect(lpAddress, dwSize, flNewProtect, out lpflOldProtect);
        }

        internal static void GetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo)
        {
            if (getNativeSystemInfo == null)
                InitNatives();

            getNativeSystemInfo(out lpSystemInfo);
        }

        internal static Pointer GetProcAddress(Pointer hModule, Pointer procName)
        {
            if (getProcAddress == null)
                InitNatives();

            return getProcAddress(hModule, procName);
        }

        internal static void InitNatives()
        {
            if (nativeInitialized)
                return;

            var kernel32 = new ExportResolver("kernel32.dll");
            kernel32.CacheAllExports(); // A bit overkill, but it is much more efficient.
            loadLibrary = Marshal.GetDelegateForFunctionPointer<DLoadLibrary>(kernel32["LoadLibraryA"]);
            freeLibrary = Marshal.GetDelegateForFunctionPointer<DFreeLibrary>(kernel32["FreeLibrary"]);
            virtualAlloc = Marshal.GetDelegateForFunctionPointer<DVirtualAlloc>(kernel32["VirtualAlloc"]);
            virtualFree = Marshal.GetDelegateForFunctionPointer<DVirtualFree>(kernel32["VirtualFree"]);
            virtualProtect = Marshal.GetDelegateForFunctionPointer<DVirtualProtect>(kernel32["VirtualProtect"]);
            getNativeSystemInfo = Marshal.GetDelegateForFunctionPointer<DGetNativeSystemInfo>(kernel32["GetNativeSystemInfo"]);
            getProcAddress = Marshal.GetDelegateForFunctionPointer<DGetProcAddress>(kernel32["GetProcAddress"]);
            nativeInitialized = true;
        }
    }
}
