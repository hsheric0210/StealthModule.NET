using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        private static Pointer[] BuildImportTable(ref ImageNtHeaders ntHeadersData, Pointer moduleBaseAddress)
        {
            NativeMethods.RtlGetVersion(out var osVersion);

            var apiSetDict = new Dictionary<string, string>();
            if (osVersion.MajorVersion >= 10)
                apiSetDict = NativeMethods.GetApiSetMapping();

            var importModules = new List<Pointer>();
            var numEntries = ntHeadersData.OptionalHeader.ImportTable.Size / NativeSizes.IMAGE_IMPORT_DESCRIPTOR;
            var importDescriptorAddress = moduleBaseAddress + ntHeadersData.OptionalHeader.ImportTable.VirtualAddress;
            for (uint i = 0; i != numEntries; i++, importDescriptorAddress += NativeSizes.IMAGE_IMPORT_DESCRIPTOR)
            {
                var importDescriptor = importDescriptorAddress.Read<ImageImportDescriptor>();
                if (importDescriptor.Name == 0)
                    break;

                var dllName = Marshal.PtrToStringAnsi(moduleBaseAddress + importDescriptor.Name);

                if (osVersion.MajorVersion >= 10 && (dllName.StartsWith("api-") || dllName.StartsWith("ext-")) && apiSetDict.TryGetValue(dllName, out var apiSetName) && apiSetName.Length > 0)
                {
                    // Not all API set DLL's have a registered host mapping
                    dllName = apiSetName;
                }

                var handle = ExportResolver.GetModuleHandle(dllName);
                if (handle.IsInvalidHandle())
                    handle = NativeMethods.LoadLibrary(dllName);

                if (handle.IsInvalidHandle())
                {
                    foreach (var m in importModules)
                        NativeMethods.FreeLibrary(m);

                    importModules.Clear();
                    throw new ModuleException("Can't load libary " + Marshal.PtrToStringAnsi(moduleBaseAddress + importDescriptor.Name));
                }

                importModules.Add(handle);

                Pointer thunkRef, functionRef;
                if (importDescriptor.OriginalFirstThunk > 0)
                {
                    thunkRef = moduleBaseAddress + importDescriptor.OriginalFirstThunk;
                    functionRef = moduleBaseAddress + importDescriptor.FirstThunk;
                }
                else
                {
                    // no hint table
                    thunkRef = moduleBaseAddress + importDescriptor.FirstThunk;
                    functionRef = moduleBaseAddress + importDescriptor.FirstThunk;
                }

                for (var pointerSize = Pointer.Size; ; thunkRef += pointerSize, functionRef += pointerSize)
                {
                    Pointer readThunkRef = thunkRef.Read(), writeFuncRef;
                    if (readThunkRef == Pointer.Zero)
                        break;

                    if (NativeMethods.IMAGE_SNAP_BY_ORDINAL(readThunkRef))
                    {
                        // import by ordinal
                        writeFuncRef = NativeMethods.GetProcAddress(handle, unchecked((ushort)(uint)NativeMethods.IMAGE_ORDINAL(readThunkRef)));
                    }
                    else
                    {
                        // import by name
                        writeFuncRef = NativeMethods.GetProcAddress(handle, Marshal.PtrToStringAnsi(moduleBaseAddress + readThunkRef + NativeOffsets.IMAGE_IMPORT_BY_NAME_Name));
                    }

                    if (writeFuncRef == Pointer.Zero)
                        throw new ModuleException("Can't get adress for imported function");

                    functionRef.Write(writeFuncRef);
                }
            }

            return importModules.ToArray();
        }
    }
}
