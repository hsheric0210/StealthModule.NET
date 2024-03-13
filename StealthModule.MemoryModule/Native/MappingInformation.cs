using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace StealthModule.MemoryModule.Native
{
    #region Structs

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

    #endregion

    #region Enums

    [Flags]
    public enum SectionTypes : uint
    {
        None = 0,
        SEC_IMAGE = 0x1000000,
        SEC_RESERVE = 0x4000000,
        SEC_COMMIT = 0x08000000,
        SEC_NOCACHE = 0x10000000,
        SEC_IMAGE_NO_EXECUTE = 0x11000000,
        SEC_WRITECOMBINE = 0x40000000,
        SEC_LARGE_PAGES = 0x80000000,
    }

    #endregion
}
