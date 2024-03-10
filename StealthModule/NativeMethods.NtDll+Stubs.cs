using System;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        internal static void RtlInitUnicodeString(ref UNICODE_STRING destinationString, string sourceString)
        {
            if (rtlInitUnicodeString == null)
                InitNtDLL();

            rtlInitUnicodeString(ref destinationString, sourceString);
        }

        internal static void RtlZeroMemory(IntPtr destination, int length)
        {
            if (rtlZeroMemory == null)
                InitNtDLL();

            rtlZeroMemory(destination, length);
        }

        internal static NTSTATUS NtCreateSection(ref IntPtr sectionHandle, AccessMask desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, MemoryProtection sectionPageProtection, SectionTypes AllocationAttributes, IntPtr fileHandle)
        {
            if (ntCreateSection == null)
                InitNtDLL();

            return ntCreateSection(ref sectionHandle, (uint)desiredAccess, objectAttributes, ref maximumSize, sectionPageProtection, AllocationAttributes, fileHandle);
        }

        internal static NTSTATUS NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, SectionTypes allocationType, MemoryProtection win32Protect)
        {
            if (ntMapViewOfSection == null)
                InitNtDLL();

            return ntMapViewOfSection(sectionHandle, processHandle, ref baseAddress, zeroBits, commitSize, sectionOffset, ref viewSize, inheritDisposition, allocationType, win32Protect);
        }

        internal static NTSTATUS NtOpenFile(ref IntPtr fileHandle, FileAccessFlags desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, ref IO_STATUS_BLOCK ioStatusBlock, FileShareFlags shareAccess, FileOpenFlags openOptions)
        {
            if (ntOpenFile == null)
                InitNtDLL();

            return ntOpenFile(ref fileHandle, desiredAccess, ref objectAttributes, ref ioStatusBlock, shareAccess, openOptions);
        }

        internal static NTSTATUS NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, AllocationType allocationType, MemoryProtection protect)
        {
            if (ntAllocateVirtualMemory == null)
                InitNtDLL();

            return ntAllocateVirtualMemory(processHandle, ref baseAddress, zeroBits, ref regionSize, allocationType, protect);
        }

        internal static NTSTATUS NtFreeVirtualMemory(IntPtr processHandle, IntPtr baseAddress, ref IntPtr regionSize, AllocationType freeType)
        {
            if (ntFreeVirtualMemory == null)
                InitNtDLL();

            return ntFreeVirtualMemory(processHandle, baseAddress, ref regionSize, freeType);
        }

        internal static NTSTATUS NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength, out uint bytesWritten)
        {
            if (ntWriteVirtualMemory == null)
                InitNtDLL();

            return ntWriteVirtualMemory(processHandle, baseAddress, buffer, bufferLength, out bytesWritten);
        }

        internal static NTSTATUS NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, MemoryProtection newProtect, out MemoryProtection oldProtect)
        {
            if (ntProtectVirtualMemory == null)
                InitNtDLL();

            return ntProtectVirtualMemory(processHandle, ref baseAddress, ref regionSize, newProtect, out oldProtect);
        }

        internal static NTSTATUS NtQuerySystemInformation(SystemInformationClass systemInformationClass, IntPtr systemInformation, uint systemInformationLength, out uint returnLength)
        {
            if (ntQuerySystemInformation == null)
                InitNtDLL();

            return ntQuerySystemInformation(systemInformationClass, systemInformation, systemInformationLength, out returnLength);
        }

        internal static NTSTATUS LdrLoadDll(IntPtr pathToFile, uint flags, ref UNICODE_STRING moduleFileName, out IntPtr moduleHandle)
        {
            if (ldrLoadDll == null)
                InitNtDLL();

            return ldrLoadDll(pathToFile, flags, ref moduleFileName, out moduleHandle);
        }

        internal static NTSTATUS LdrUnloadDll(IntPtr moduleHandle)
        {
            if (ldrUnloadDll == null)
                InitNtDLL();

            return ldrUnloadDll(moduleHandle);
        }

        internal static NTSTATUS LdrGetProcedureAddress(IntPtr moduleHandle, IntPtr functionName, IntPtr ordinal, out IntPtr functionAddress)
        {
            if (ldrGetProcedureAddress == null)
                InitNtDLL();

            return ldrGetProcedureAddress(moduleHandle, functionName, ordinal, out functionAddress);
        }
    }
}
