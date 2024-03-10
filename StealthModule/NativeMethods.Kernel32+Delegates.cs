using System;

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
    }
}
