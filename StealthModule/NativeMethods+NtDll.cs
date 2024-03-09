using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        internal static class Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate void RtlInitUnicodeString(ref UNICODE_STRING destinationString, [MarshalAs(UnmanagedType.LPWStr)] string sourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtCreateSection(ref IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, uint allocationType, uint win32Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtOpenFile(ref IntPtr fileHandle, FileAccessFlags desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, ref IO_STATUS_BLOCK ioStatusBlock, FileShareFlags shareAccess, FileOpenFlags openOptions);
        }

        static bool ntdllInitialized;
        private static Delegates.RtlInitUnicodeString rtlInitUnicodeString;
        private static Delegates.NtCreateSection ntCreateSection;
        private static Delegates.NtMapViewOfSection ntMapViewOfSection;
        private static Delegates.NtOpenFile ntOpenFile;

        internal static void RtlInitUnicodeString(ref UNICODE_STRING destinationString, string sourceString)
        {
            if (rtlInitUnicodeString == null)
                InitNtDll();

            rtlInitUnicodeString(ref destinationString, sourceString);
        }

        internal static NTSTATUS NtCreateSection(ref IntPtr sectionHandle, ACCESS_MASK desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, MemoryProtection sectionPageProtection, SectionTypes AllocationAttributes, IntPtr fileHandle)
        {
            if (ntCreateSection == null)
                InitNtDll();

            return ntCreateSection(ref sectionHandle, (uint)desiredAccess, objectAttributes, ref maximumSize, (uint)sectionPageProtection, (uint)AllocationAttributes, fileHandle);
        }

        internal static NTSTATUS NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, SectionTypes allocationType, MemoryProtection win32Protect)
        {
            if (ntMapViewOfSection == null)
                InitNtDll();

            return ntMapViewOfSection(sectionHandle, processHandle, ref baseAddress, zeroBits, commitSize, sectionOffset, ref viewSize, inheritDisposition, (uint)allocationType, (uint)win32Protect);
        }

        internal static NTSTATUS NtOpenFile(ref IntPtr fileHandle, FileAccessFlags desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, ref IO_STATUS_BLOCK ioStatusBlock, FileShareFlags shareAccess, FileOpenFlags openOptions)
        {
            if (ntOpenFile == null)
                InitNtDll();

            return ntOpenFile(ref fileHandle, desiredAccess, ref objectAttributes, ref ioStatusBlock, shareAccess, openOptions);
        }

        internal static void InitNtDll()
        {
            if (ntdllInitialized)
                return;

            var kernel32 = new ExportResolver("ntdll.dll");
            kernel32.CacheAllExports(); // A bit overkill, but it is much more efficient.
            rtlInitUnicodeString = (Delegates.RtlInitUnicodeString)kernel32.GetExport("RtlInitUnicodeString", typeof(Delegates.RtlInitUnicodeString));
            ntCreateSection = (Delegates.NtCreateSection)kernel32.GetExport("NtCreateSection", typeof(Delegates.NtCreateSection));
            ntMapViewOfSection = (Delegates.NtMapViewOfSection)kernel32.GetExport("NtMapViewOfSection", typeof(Delegates.NtMapViewOfSection));
            ntOpenFile = (Delegates.NtOpenFile)kernel32.GetExport("NtOpenFile", typeof(Delegates.NtOpenFile));
            ntdllInitialized = true;
        }
    }
}
