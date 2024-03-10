using System;
using System.Runtime.InteropServices;
using static StealthModule.NativeMethods.NtDllDelegates;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        internal static class NtDllDelegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate void RtlInitUnicodeString(ref UNICODE_STRING destinationString, [MarshalAs(UnmanagedType.LPWStr)] string sourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate void RtlZeroMemory(IntPtr destination, int length);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtCreateSection(ref IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, MemoryProtection sectionPageProtection, SectionTypes allocationAttributes, IntPtr fileHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, SectionTypes allocationType, MemoryProtection win32Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtOpenFile(ref IntPtr fileHandle, FileAccessFlags desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, ref IO_STATUS_BLOCK ioStatusBlock, FileShareFlags shareAccess, FileOpenFlags openOptions);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, AllocationType allocationType, MemoryProtection protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtFreeVirtualMemory(IntPtr processHandle, IntPtr baseAddress, ref IntPtr regionSize, AllocationType freeType);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength, out uint bytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, MemoryProtection newProtect, out MemoryProtection oldProtect);
        }

        static bool ntdllInitialized;
        private static RtlInitUnicodeString rtlInitUnicodeString;
        private static RtlZeroMemory rtlZeroMemory;
        private static NtCreateSection ntCreateSection;
        private static NtMapViewOfSection ntMapViewOfSection;
        private static NtOpenFile ntOpenFile;
        private static NtProtectVirtualMemory ntProtectVirtualMemory;
        private static NtWriteVirtualMemory ntWriteVirtualMemory;
        private static NtAllocateVirtualMemory ntAllocateVirtualMemory;
        private static NtFreeVirtualMemory ntFreeVirtualMemory;

        internal static void RtlInitUnicodeString(ref UNICODE_STRING destinationString, string sourceString)
        {
            if (rtlInitUnicodeString == null)
                InitNtDll();

            rtlInitUnicodeString(ref destinationString, sourceString);
        }

        internal static void RtlZeroMemory(IntPtr destination, int length)
        {
            if (rtlZeroMemory == null)
                InitNtDll();

            rtlZeroMemory(destination, length);
        }

        internal static NTSTATUS NtCreateSection(ref IntPtr sectionHandle, AccessMask desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, MemoryProtection sectionPageProtection, SectionTypes AllocationAttributes, IntPtr fileHandle)
        {
            if (ntCreateSection == null)
                InitNtDll();

            return ntCreateSection(ref sectionHandle, (uint)desiredAccess, objectAttributes, ref maximumSize, sectionPageProtection, AllocationAttributes, fileHandle);
        }

        internal static NTSTATUS NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, SectionTypes allocationType, MemoryProtection win32Protect)
        {
            if (ntMapViewOfSection == null)
                InitNtDll();

            return ntMapViewOfSection(sectionHandle, processHandle, ref baseAddress, zeroBits, commitSize, sectionOffset, ref viewSize, inheritDisposition, allocationType, win32Protect);
        }

        internal static NTSTATUS NtOpenFile(ref IntPtr fileHandle, FileAccessFlags desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, ref IO_STATUS_BLOCK ioStatusBlock, FileShareFlags shareAccess, FileOpenFlags openOptions)
        {
            if (ntOpenFile == null)
                InitNtDll();

            return ntOpenFile(ref fileHandle, desiredAccess, ref objectAttributes, ref ioStatusBlock, shareAccess, openOptions);
        }

        internal static NTSTATUS NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, AllocationType allocationType, MemoryProtection protect)
        {
            if (ntAllocateVirtualMemory == null)
                InitNtDll();

            return ntAllocateVirtualMemory(processHandle, ref baseAddress, zeroBits, ref regionSize, allocationType, protect);
        }

        internal static NTSTATUS NtFreeVirtualMemory(IntPtr processHandle, IntPtr baseAddress, ref IntPtr regionSize, AllocationType freeType)
        {
            if (ntFreeVirtualMemory == null)
                InitNtDll();

            return ntFreeVirtualMemory(processHandle, baseAddress, ref regionSize, freeType);
        }

        internal static NTSTATUS NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength, out uint bytesWritten)
        {
            if (ntWriteVirtualMemory == null)
                InitNtDll();

            return ntWriteVirtualMemory(processHandle, baseAddress, buffer, bufferLength, out bytesWritten);
        }

        internal static NTSTATUS NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, MemoryProtection newProtect, out MemoryProtection oldProtect)
        {
            if (ntProtectVirtualMemory == null)
                InitNtDll();

            return ntProtectVirtualMemory(processHandle, ref baseAddress, ref regionSize, newProtect, out oldProtect);
        }

        internal static void InitNtDll()
        {
            if (ntdllInitialized)
                return;

            var kernel32 = new ExportResolver("ntdll.dll");
            kernel32.CacheAllExports(); // A bit overkill, but it is much more efficient.
            rtlInitUnicodeString = kernel32.GetExport<RtlInitUnicodeString>("RtlInitUnicodeString");
            rtlZeroMemory = kernel32.GetExport<RtlZeroMemory>("RtlZeroMemory");
            ntCreateSection = kernel32.GetExport<NtCreateSection>("NtCreateSection");
            ntMapViewOfSection = kernel32.GetExport<NtMapViewOfSection>("NtMapViewOfSection");
            ntOpenFile = kernel32.GetExport<NtOpenFile>("NtOpenFile");
            ntAllocateVirtualMemory = kernel32.GetExport<NtAllocateVirtualMemory>("NtAllocateVirtualMemory");
            ntFreeVirtualMemory = kernel32.GetExport<NtFreeVirtualMemory>("NtFreeVirtualMemory");
            ntWriteVirtualMemory = kernel32.GetExport<NtWriteVirtualMemory>("NtWriteVirtualMemory");
            ntProtectVirtualMemory = kernel32.GetExport<NtProtectVirtualMemory>("NtProtectVirtualMemory");
            ntdllInitialized = true;
        }
    }
}
