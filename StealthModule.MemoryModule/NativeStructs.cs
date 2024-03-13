using System;
using System.Runtime.InteropServices;

namespace StealthModule.MemoryModule
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

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ANSI_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName; // -> UNICODE_STRING
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }

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
}
