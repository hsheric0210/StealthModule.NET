using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace StealthModule.MemoryModule.Native
{
    #region Structs

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

    /// <summary>
    /// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_basic_information.htm
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_BASIC_INFORMATION
    {
        public uint Reserved;
        public uint TimerResolution;
        public uint PageSize;
        public uint NumberOfPhysicalPages;
        public uint LowestPhysicalPageNumber;
        public uint HighestPhysicalPageNumber;
        public uint AllocationGranularity;
        public IntPtr MinimumUserModeAddress;
        public IntPtr MaximumUserModeAddress;
        public IntPtr ActiveProcessorsAffinityMask;
        public uint NumberOfProcessors;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OSVersionInfoEx
    {
        public uint OSVersionInfoSize;
        public uint MajorVersion;
        public uint MinorVersion;
        public uint BuildNumber;
        public uint PlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string CSDVersion;
        public ushort ServicePackMajor;
        public ushort ServicePackMinor;
        public ushort SuiteMask;
        public byte ProductType;
        public byte Reserved;
    }

    #endregion

    #region Enums

    /// <summary>
    /// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm
    /// </summary>
    public enum SystemInformationClass : uint
    {
        SystemBasicInformation = 0x00,
    }

    #endregion
}
