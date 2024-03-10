using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    internal partial class NativeMethods
    {
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

        internal static NTSTATUS NtQuerySystemInformation(SystemInformationClass systemInformationClass, IntPtr systemInformation, uint systemInformationLength, out uint returnLength)
        {
            if (ntQuerySystemInformation == null)
                InitNtDll();

            return ntQuerySystemInformation(systemInformationClass, systemInformation, systemInformationLength, out returnLength);
        }

        internal static NTSTATUS LdrLoadDll(string pathToFile, uint flags, IntPtr moduleFileName, out IntPtr moduleHandle)
        {
            if (ldrLoadDll == null)
                InitNtDll();

            return ldrLoadDll(pathToFile, flags, moduleFileName, out moduleHandle);
        }

        internal static NTSTATUS LdrUnloadDll(IntPtr moduleHandle)
        {
            if (ldrUnloadDll == null)
                InitNtDll();

            return ldrUnloadDll(moduleHandle);
        }

        internal static NTSTATUS LdrGetProcedureAddress(IntPtr moduleHandle, IntPtr functionName, IntPtr ordinal, out IntPtr functionAddress)
        {
            if (ldrGetProcedureAddress == null)
                InitNtDll();

            return ldrGetProcedureAddress(moduleHandle, functionName, ordinal, out functionAddress);
        }
    }
}
