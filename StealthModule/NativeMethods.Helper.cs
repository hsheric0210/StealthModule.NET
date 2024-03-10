using System;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace StealthModule
{
    internal partial class NativeMethods
    {
        internal static Pointer AllocVirtualMemory(Pointer baseAddress, IntPtr size, AllocationType allocationType, MemoryProtection protect)
        {
            IntPtr baseAddressPtr = baseAddress;
            var status = NtAllocateVirtualMemory(GetCurrentProcess(), ref baseAddressPtr, IntPtr.Zero, ref size, allocationType, protect);
            if (!NT_SUCCESS(status))
                return Pointer.Zero;

            return baseAddressPtr;
        }

        internal static bool ProtectVirtualMemory(Pointer baseAddress, IntPtr size, MemoryProtection protect)
            => ProtectVirtualMemory(baseAddress, size, protect, out _);

        internal static bool ProtectVirtualMemory(Pointer baseAddress, IntPtr size, MemoryProtection protect, out MemoryProtection prevProtect)
        {
            IntPtr baseAddressPtr = baseAddress;
            return NT_SUCCESS(NtProtectVirtualMemory(GetCurrentProcess(), ref baseAddressPtr, ref size, protect, out prevProtect));
        }

        internal static bool FreeVirtualMemory(Pointer baseAddress, IntPtr size, AllocationType freeType)
            => NT_SUCCESS(NtFreeVirtualMemory(GetCurrentProcess(), baseAddress, ref size, freeType));

        internal static bool GetSystemPageSize(out uint pageSize)
        {
            pageSize = 0;

            var basicInformationSize = Marshal.SizeOf(typeof(SYSTEM_BASIC_INFORMATION));
            var buffer = Marshal.AllocHGlobal(basicInformationSize);
            try
            {
                var status = NtQuerySystemInformation(SystemInformationClass.SystemBasicInformation, buffer, (uint)basicInformationSize, out var returnLength);
                if (!NT_SUCCESS(status) || basicInformationSize != returnLength)
                    return false;

                var info = (SYSTEM_BASIC_INFORMATION)Marshal.PtrToStructure(buffer, typeof(SYSTEM_BASIC_INFORMATION));
                pageSize = info.PageSize;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return true;
        }

        internal static Pointer LoadLibrary(string dllPath)
        {
            var moduleName = new UNICODE_STRING();
            RtlInitUnicodeString(ref moduleName, dllPath);

            var status = LdrLoadDll(IntPtr.Zero, 0, ref moduleName, out var moduleHandle);
            if (!NT_SUCCESS(status) || moduleHandle == IntPtr.Zero)
                return Pointer.Zero;

            return moduleHandle;
        }

        internal static bool FreeLibrary(Pointer handle)
            => NT_SUCCESS(LdrUnloadDll(handle));

        internal static Pointer GetProcAddress(Pointer handle, string functionName)
        {
            var functionNameAnsiBuffer = Marshal.StringToCoTaskMemAnsi(functionName);
            var functionNameAnsi = new ANSI_STRING
            {
                Length = (ushort)functionName.Length,
                MaximumLength = (ushort)(functionName.Length * 2),
                Buffer = functionNameAnsiBuffer,
            };

            var functionNameBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(functionNameAnsi));
            try
            {
                Marshal.StructureToPtr(functionNameAnsi, functionNameBuffer, false);
                var status = LdrGetProcedureAddress(handle, functionNameBuffer, IntPtr.Zero, out var procAddress);
                if (!NT_SUCCESS(status))
                    return Pointer.Zero;

                return procAddress;
            }
            finally
            {
                Marshal.FreeHGlobal(functionNameBuffer);
                Marshal.FreeCoTaskMem(functionNameAnsiBuffer);
            }
        }

        internal static Pointer GetProcAddress(Pointer handle, int ordinal)
        {
            var status = LdrGetProcedureAddress(handle, IntPtr.Zero, (IntPtr)ordinal, out var procAddress);
            if (!NT_SUCCESS(status))
                return Pointer.Zero;

            return procAddress;
        }
    }
}
