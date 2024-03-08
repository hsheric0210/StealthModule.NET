using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    /// <summary>
    /// SYSTEM_INFO
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SystemInfo
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    };
}
