using System;
using System.Runtime.InteropServices;

namespace StealthModule.MemoryModule.Native
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessBasicInformation
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public int InheritedFromUniqueProcessId;
    }

    public enum ProcessInfoClass : uint
    {
        ProcessBasicInformation = 0,
    };
}
