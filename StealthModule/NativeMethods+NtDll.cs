﻿using System;
using System.Runtime.InteropServices;
using static StealthModule.NativeMethods.Delegates;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        internal static class Delegates
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
            internal delegate NTSTATUS NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, MemoryProtection newProtect, out MemoryProtection oldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength, out uint bytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, AllocationType allocationType, MemoryProtection protect);
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

        internal static NTSTATUS NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, MemoryProtection newProtect, out MemoryProtection oldProtect)
        {
            if (ntProtectVirtualMemory == null)
                InitNtDll();

            return ntProtectVirtualMemory(processHandle, ref baseAddress, ref regionSize, newProtect, out oldProtect);
        }

        internal static NTSTATUS NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength, out uint bytesWritten)
        {
            if (ntWriteVirtualMemory == null)
                InitNtDll();

            return ntWriteVirtualMemory(processHandle, baseAddress, buffer, bufferLength, out bytesWritten);
        }

        internal static NTSTATUS NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, AllocationType allocationType, MemoryProtection protect)
        {
            if (ntAllocateVirtualMemory == null)
                InitNtDll();

            return ntAllocateVirtualMemory(processHandle, ref baseAddress, zeroBits, ref regionSize, allocationType, protect);
        }

        internal static void InitNtDll()
        {
            if (ntdllInitialized)
                return;

            var kernel32 = new ExportResolver("ntdll.dll");
            kernel32.CacheAllExports(); // A bit overkill, but it is much more efficient.
            rtlInitUnicodeString = (RtlInitUnicodeString)kernel32.GetExport("RtlInitUnicodeString", typeof(RtlInitUnicodeString));
            rtlZeroMemory = (RtlZeroMemory)kernel32.GetExport("RtlZeroMemory", typeof(RtlZeroMemory));
            ntCreateSection = (NtCreateSection)kernel32.GetExport("NtCreateSection", typeof(NtCreateSection));
            ntMapViewOfSection = (NtMapViewOfSection)kernel32.GetExport("NtMapViewOfSection", typeof(NtMapViewOfSection));
            ntOpenFile = (NtOpenFile)kernel32.GetExport("NtOpenFile", typeof(NtOpenFile));
            ntProtectVirtualMemory = (NtProtectVirtualMemory)kernel32.GetExport("NtProtectVirtualMemory", typeof(NtProtectVirtualMemory));
            ntWriteVirtualMemory = (NtWriteVirtualMemory)kernel32.GetExport("NtWriteVirtualMemory", typeof(NtWriteVirtualMemory));
            ntAllocateVirtualMemory = (NtAllocateVirtualMemory)kernel32.GetExport("NtAllocateVirtualMemory", typeof(NtAllocateVirtualMemory));
            ntdllInitialized = true;
        }
    }
}
