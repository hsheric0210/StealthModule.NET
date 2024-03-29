﻿using System;
using System.Runtime.InteropServices;
using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule
{
    internal static partial class NativeMethods
    {
        internal static class NtDllDelegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate void RtlInitUnicodeString(ref UnicodeString destinationString, [MarshalAs(UnmanagedType.LPWStr)] string sourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate void RtlZeroMemory(IntPtr destination, int length);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS RtlGetVersion(out OSVersionInfoEx VersionInformation);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS RtlAddFunctionTable(IntPtr functionTable, uint entryCount, ulong baseAddress);

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

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtQuerySystemInformation(SystemInformationClass systemInformationClass, IntPtr systemInformation, uint systemInformationLength, out uint returnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS NtQueryInformationProcess(IntPtr processHandle, ProcessInfoClass processInformationClass, IntPtr processInformation, int processInformationLength, out uint returnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS LdrLoadDll(IntPtr pathToFile, uint flags, ref UnicodeString moduleFileName, out IntPtr moduleHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS LdrUnloadDll(IntPtr moduleHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            internal delegate NTSTATUS LdrGetProcedureAddress(IntPtr moduleHandle, IntPtr functionName, IntPtr ordinal, out IntPtr functionAddress);
        }
    }
}
