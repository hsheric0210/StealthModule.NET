using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace StealthModule
{
    internal static partial class NativeMethods
    {
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
