using System;
using System.Collections.Generic;
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
            if (status != NTSTATUS.Success || moduleHandle == IntPtr.Zero || ((Pointer)moduleHandle).IsInvalidHandle())
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

        internal static ProcessBasicInformation QueryProcessBasicInformation(IntPtr processHandle)
        {
            var info = new ProcessBasicInformation();
            var infoSize = Marshal.SizeOf(info);

            var buffer = Marshal.AllocHGlobal(infoSize);
            try
            {
                RtlZeroMemory(buffer, infoSize);
                Marshal.StructureToPtr((object)info, buffer, true);

                var status = NtQueryInformationProcess(processHandle, ProcessInfoClass.ProcessBasicInformation, buffer, infoSize, out var returnLength);
                if (!NT_SUCCESS(status))
                    throw new ModuleException("NtQueryInformationProcess ProcessBasicInformation returned NTSTATUS " + status);

                info = (ProcessBasicInformation)Marshal.PtrToStructure(buffer, typeof(ProcessBasicInformation));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return info;
        }

        /// <author>Ruben Boonen (@FuzzySec)</author>
        internal static Dictionary<string, string> GetApiSetMapping()
        {
            var info = QueryProcessBasicInformation(GetCurrentProcess());
            var apiSetMapOffset = Pointer.Is64Bit ? 0x68 : 0x38;

            var apiSetMap = new Dictionary<string, string>();

            var apiSetNamespaceAddress = ((Pointer)info.PebBaseAddress + apiSetMapOffset).Read();
            var apiSetNamespace = (ApiSetNamespace)Marshal.PtrToStructure(apiSetNamespaceAddress, typeof(ApiSetNamespace));

            var entrySize = Marshal.SizeOf(typeof(ApiSetNamespaceEntry));
            for (var i = 0; i < apiSetNamespace.Count; i++)
            {
                var entryAddress = apiSetNamespaceAddress + apiSetNamespace.EntryOffset + i * entrySize;
                var entry = entryAddress.Read<ApiSetNamespaceEntry>();

                var entryNameAddress = apiSetNamespaceAddress + entry.NameOffset;
                var entryNameLength = entry.NameLength / 2;
                var entryName = Marshal.PtrToStringUni(entryNameAddress, entryNameLength) + ".dll";

                var valueEntryAddress = apiSetNamespaceAddress + entry.ValueOffset;
                var valueEntry = valueEntryAddress.Read<ApiSetValueEntry>();
                var value = string.Empty;
                if (valueEntry.ValueCount != 0)
                {
                    var valueAddress = apiSetNamespaceAddress + valueEntry.ValueOffset;
                    var valueLength = valueEntry.ValueCount / 2;
                    value = Marshal.PtrToStringUni(valueAddress, valueLength);
                }

                apiSetMap.Add(entryName, value);
            }

            return apiSetMap;
        }
    }
}
