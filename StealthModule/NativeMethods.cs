using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    internal class NativeMethods
    {
        internal delegate IntPtr DVirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
        internal delegate IntPtr DLoadLibrary(IntPtr lpFileName);
        internal delegate bool DVirtualFree(IntPtr lpAddress, IntPtr dwSize, AllocationType dwFreeType);
        internal delegate bool DVirtualProtect(IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        internal delegate bool DFreeLibrary(IntPtr hModule);
        internal delegate void DGetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);
        internal delegate IntPtr DGetProcAddress(IntPtr hModule, IntPtr procName);

        static bool nativeInitialized;
        private static DLoadLibrary loadLibrary;
        private static DFreeLibrary freeLibrary;
        private static DVirtualAlloc virtualAlloc;
        private static DVirtualFree virtualFree;
        private static DVirtualProtect virtualProtect;
        private static DGetNativeSystemInfo getNativeSystemInfo;
        private static DGetProcAddress getProcAddress;

        internal static DLoadLibrary LoadLibrary
        {
            get
            {
                if (loadLibrary == null)
                    InitNatives();

                return loadLibrary;
            }
            set => loadLibrary = value;
        }

        internal static DFreeLibrary FreeLibrary
        {
            get
            {
                if (freeLibrary == null)
                    InitNatives();

                return freeLibrary;
            }
            set => freeLibrary = value;
        }

        internal static DVirtualAlloc VirtualAlloc
        {
            get
            {
                if (virtualAlloc == null)
                    InitNatives();

                return virtualAlloc;
            }
            set => virtualAlloc = value;
        }

        internal static DVirtualFree VirtualFree
        {
            get
            {
                if (virtualFree == null)
                    InitNatives();

                return virtualFree;
            }
            set => virtualFree = value;
        }

        internal static DVirtualProtect VirtualProtect
        {
            get
            {
                if (virtualProtect == null)
                    InitNatives();

                return virtualProtect;
            }
            set => virtualProtect = value;
        }

        internal static DGetNativeSystemInfo GetNativeSystemInfo
        {
            get
            {
                if (getNativeSystemInfo == null)
                    InitNatives();

                return getNativeSystemInfo;
            }
            set => getNativeSystemInfo = value;
        }

        internal static DGetProcAddress GetProcAddress
        {
            get
            {
                if (getProcAddress == null)
                    InitNatives();

                return getProcAddress;
            }
            set => getProcAddress = value;
        }

        // Equivalent to the IMAGE_FIRST_SECTION macro
        internal static IntPtr IMAGE_FIRST_SECTION(IntPtr pNTHeader, ushort ntheader_FileHeader_SizeOfOptionalHeader) => pNTHeader.Add(Of.IMAGE_NT_HEADERS_OptionalHeader + ntheader_FileHeader_SizeOfOptionalHeader);

        // Equivalent to the IMAGE_FIRST_SECTION macro
        internal static int IMAGE_FIRST_SECTION(int lfanew, ushort ntheader_FileHeader_SizeOfOptionalHeader) => lfanew + Of.IMAGE_NT_HEADERS_OptionalHeader + ntheader_FileHeader_SizeOfOptionalHeader;

        // Equivalent to the IMAGE_ORDINAL32/64 macros
        internal static IntPtr IMAGE_ORDINAL(IntPtr ordinal) => (IntPtr)(int)(unchecked((ulong)ordinal.ToInt64()) & 0xffff);

        // Equivalent to the IMAGE_SNAP_BY_ORDINAL32/64 macro
        internal static bool IMAGE_SNAP_BY_ORDINAL(IntPtr ordinal) => IntPtr.Size == 8 ? (ordinal.ToInt64() < 0) : (ordinal.ToInt32() < 0);

        internal static void InitNatives()
        {
            if (nativeInitialized)
                return;

            var kernel32 = Resolver.GetModuleHandle("kernel32.dll");
            var exports = new string[] {
                 "LoadLibraryA",
                 "FreeLibrary",
                 "VirtualAlloc",
                 "VirtualFree",
                 "VirtualProtect",
                 "GetNativeSystemInfo",
                 "GetProcAddress",
            };

            var addresses = Resolver.GetProcAddressBatch(kernel32, exports, true);
            LoadLibrary = Marshal.GetDelegateForFunctionPointer<DLoadLibrary>(addresses[0]);
            FreeLibrary = Marshal.GetDelegateForFunctionPointer<DFreeLibrary>(addresses[1]);
            VirtualAlloc = Marshal.GetDelegateForFunctionPointer<DVirtualAlloc>(addresses[2]);
            VirtualFree = Marshal.GetDelegateForFunctionPointer<DVirtualFree>(addresses[3]);
            VirtualProtect = Marshal.GetDelegateForFunctionPointer<DVirtualProtect>(addresses[4]);
            GetNativeSystemInfo = Marshal.GetDelegateForFunctionPointer<DGetNativeSystemInfo>(addresses[5]);
            GetProcAddress = Marshal.GetDelegateForFunctionPointer<DGetProcAddress>(addresses[6]);
            nativeInitialized = true;
        }
    }
}
