using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        private static ICollection<Pointer> BuildImportTable(ref ImageNtHeaders ntHeadersData, Pointer moduleBaseAddress)
        {
            NativeMethods.RtlGetVersion(out var osVersion);

            var apiSetDict = new Dictionary<string, string>();
            if (osVersion.MajorVersion >= 10)
            {
                apiSetDict = NativeMethods.GetApiSetMapping();
            }

            var importModules = new List<Pointer>();

            // Import Table
            var numEntries = ntHeadersData.OptionalHeader.ImportTable.Size / NativeSizes.IMAGE_IMPORT_DESCRIPTOR;
            var importDescriptorAddress = moduleBaseAddress + ntHeadersData.OptionalHeader.ImportTable.VirtualAddress;
            for (uint i = 0; i != numEntries; i++, importDescriptorAddress += NativeSizes.IMAGE_IMPORT_DESCRIPTOR)
            {
                var importDescriptor = importDescriptorAddress.Read<ImageImportDescriptor>();
                if (importDescriptor.Name == 0)
                    break;

                var dllName = Marshal.PtrToStringAnsi(moduleBaseAddress + importDescriptor.Name);
                var originalFirstThunk = importDescriptor.OriginalFirstThunk;
                var firstThunk = importDescriptor.FirstThunk;

                if (osVersion.MajorVersion >= 10 && (dllName.StartsWith("api-") || dllName.StartsWith("ext-")) && apiSetDict.TryGetValue(dllName, out var apiSetName) && apiSetName.Length > 0)
                {
                    // Not all API set DLL's have a registered host mapping
                    dllName = apiSetName;
                }

                var handle = HandleImportDescriptor(moduleBaseAddress, dllName, originalFirstThunk, firstThunk, false);

                if (handle.IsInvalidHandle())
                {
                    foreach (var m in importModules)
                        NativeMethods.FreeLibrary(m);

                    importModules.Clear();
                    throw new ModuleException("Can't load libary " + Marshal.PtrToStringAnsi(moduleBaseAddress + importDescriptor.Name));
                }

                importModules.Add(handle);

            }

            // Delayed Import Table
            numEntries = ntHeadersData.OptionalHeader.DelayImportDescriptor.Size / NativeSizes.IMAGE_IMPORT_DESCRIPTOR;
            importDescriptorAddress = moduleBaseAddress + ntHeadersData.OptionalHeader.DelayImportDescriptor.VirtualAddress;
            for (uint i = 0; i != numEntries; i++, importDescriptorAddress += NativeSizes.IMAGE_IMPORT_DESCRIPTOR)
            {
                var importDescriptor = importDescriptorAddress.Read<ImageDelayImportDescriptor>();
                if (importDescriptor.DllNameRVA == 0)
                    break;

                var dllName = Marshal.PtrToStringAnsi(moduleBaseAddress + importDescriptor.DllNameRVA);
                var originalFirstThunk = importDescriptor.ImportNameTableRVA;
                var firstThunk = importDescriptor.ImportAddressTableRVA;

                if (osVersion.MajorVersion >= 10 && (dllName.StartsWith("api-") || dllName.StartsWith("ext-")) && apiSetDict.TryGetValue(dllName, out var apiSetName) && apiSetName.Length > 0)
                {
                    // Not all API set DLL's have a registered host mapping
                    dllName = apiSetName;
                }

                var handle = HandleImportDescriptor(moduleBaseAddress, dllName, originalFirstThunk, firstThunk, true);

                if (!handle.IsInvalidHandle()) // ignore errors (because it is 'delayed')
                    importModules.Add(handle);
            }

            return importModules;
        }

        private static Pointer HandleImportDescriptor(Pointer moduleBaseAddress, string dllName, uint originalFirstThunk, uint firstThunk, bool ignoreNotFound)
        {
            var handle = ExportResolver.GetModuleHandle(dllName);
            if (handle.IsInvalidHandle())
                handle = NativeMethods.LoadLibrary(dllName);

            if (handle.IsInvalidHandle())
                return handle; // let the caller handle the error

            Pointer thunkRef, functionRef;
            if (originalFirstThunk > 0)
            {
                thunkRef = moduleBaseAddress + originalFirstThunk;
                functionRef = moduleBaseAddress + firstThunk;
            }
            else
            {
                // no hint table
                thunkRef = moduleBaseAddress + firstThunk;
                functionRef = moduleBaseAddress + firstThunk;
            }

            for (var pointerSize = Pointer.Size; ; thunkRef += pointerSize, functionRef += pointerSize)
            {
                Pointer readThunkRef = thunkRef.Read(), writeFuncRef;
                if (readThunkRef == Pointer.Zero)
                    break;

                if (NativeMethods.IMAGE_SNAP_BY_ORDINAL(readThunkRef))
                {
                    // import by ordinal
                    var ordinal = unchecked((ushort)(uint)NativeMethods.IMAGE_ORDINAL(readThunkRef));
                    writeFuncRef = NativeMethods.GetProcAddress(handle, ordinal);

                    if (writeFuncRef == Pointer.Zero && !ignoreNotFound)
                        throw new ModuleException("Can't get adress for imported function " + dllName + "!#" + ordinal);
                }
                else
                {
                    // import by name
                    var name = Marshal.PtrToStringAnsi(moduleBaseAddress + readThunkRef + NativeOffsets.IMAGE_IMPORT_BY_NAME_Name);
                    writeFuncRef = NativeMethods.GetProcAddress(handle, name);

                    if (writeFuncRef == Pointer.Zero && !ignoreNotFound)
                        throw new ModuleException("Can't get adress for imported function " + dllName + "!" + name);
                }

                functionRef.Write(writeFuncRef);
            }

            return handle;
        }
    }
}
