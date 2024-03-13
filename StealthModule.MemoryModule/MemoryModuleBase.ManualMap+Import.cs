using System.Collections.Generic;
using System.Runtime.InteropServices;
using StealthModule.Native.PE;

namespace StealthModule.MemoryModule
{
    public partial class MemoryModuleBase
    {
        protected virtual ICollection<Pointer> ResolveImports()
        {
            IDictionary<string, string> apiSetDict = null;

            NativeMethods.RtlGetVersion(out var osVersion);
            var isApiSetSupported = osVersion.MajorVersion >= 10;
            if (isApiSetSupported)
                apiSetDict = NativeMethods.GetApiSetMapping();

            var importedModuleHandles = new List<Pointer>();

            // Import Table
            var numEntries = ntHeaders.OptionalHeader.ImportTable.Size / NativeSizes.IMAGE_IMPORT_DESCRIPTOR;
            var importDescriptorAddress = BaseAddress + ntHeaders.OptionalHeader.ImportTable.VirtualAddress;
            for (var i = 0; i != numEntries; i++, importDescriptorAddress += NativeSizes.IMAGE_IMPORT_DESCRIPTOR)
            {
                var importDescriptor = importDescriptorAddress.Read<ImageImportDescriptor>();
                if (importDescriptor.Name == 0)
                    break;

                var originalDllName = Marshal.PtrToStringAnsi(BaseAddress + importDescriptor.Name);

                var originalFirstThunk = importDescriptor.OriginalFirstThunk;
                var firstThunk = importDescriptor.FirstThunk;

                var redirectedDllName = CheckForApiSetRedirect(apiSetDict, originalDllName);

                var handle = HandleImportDescriptor(redirectedDllName, originalFirstThunk, firstThunk, false);

                if (handle.IsInvalidHandle())
                {
                    foreach (var m in importedModuleHandles)
                        NativeMethods.FreeLibrary(m);

                    importedModuleHandles.Clear();
                    throw new ModuleException("Can't load required libary: " + redirectedDllName + " (" + originalDllName + ")");
                }

                importedModuleHandles.Add(handle);
            }

            // Delayed Import Table
            numEntries = ntHeaders.OptionalHeader.DelayImportDescriptor.Size / NativeSizes.IMAGE_IMPORT_DESCRIPTOR;
            importDescriptorAddress = BaseAddress + ntHeaders.OptionalHeader.DelayImportDescriptor.VirtualAddress;
            for (var i = 0; i != numEntries; i++, importDescriptorAddress += NativeSizes.IMAGE_IMPORT_DESCRIPTOR)
            {
                var importDescriptor = importDescriptorAddress.Read<ImageDelayImportDescriptor>();
                if (importDescriptor.DllNameRVA == 0)
                    break;

                var dllName = Marshal.PtrToStringAnsi(BaseAddress + importDescriptor.DllNameRVA);
                var originalFirstThunk = importDescriptor.ImportNameTableRVA;
                var firstThunk = importDescriptor.ImportAddressTableRVA;

                dllName = CheckForApiSetRedirect(apiSetDict, dllName);

                var handle = HandleImportDescriptor(dllName, originalFirstThunk, firstThunk, true);

                if (!handle.IsInvalidHandle()) // silently ignore errors (because it is *delayed*)
                    importedModuleHandles.Add(handle);
            }

            return importedModuleHandles;
        }

        protected virtual string CheckForApiSetRedirect(IDictionary<string, string> apiSetDict, string dllName)
        {
            if (apiSetDict != null
                && (dllName.StartsWith("api-") || dllName.StartsWith("ext-"))
                && apiSetDict.TryGetValue(dllName, out var apiSetName)
                && apiSetName.Length > 0) // Not all API set DLL's have a registered host mapping
            {
                dllName = apiSetName;
            }

            return dllName;
        }

        protected virtual Pointer HandleImportDescriptor(string dllName, uint thunkOffset, uint addressOffset, bool throwOnUnresolved)
        {
            var handle = functionCall.LoadLibrary(dllName);
            if (handle.IsInvalidHandle())
                return handle; // let the caller handle the error

            var functionRef = BaseAddress + addressOffset;
            var thunkRef = thunkOffset > 0
                ? BaseAddress + thunkOffset
                : BaseAddress + addressOffset; // no hint table

            for (var pointerSize = Pointer.Size; ; thunkRef += pointerSize, functionRef += pointerSize)
            {
                Pointer readThunkRef = thunkRef.Read(), writeFuncRef;
                if (readThunkRef == Pointer.Zero)
                    break;

                if (NativeMethods.IMAGE_SNAP_BY_ORDINAL(readThunkRef))
                {
                    // import by ordinal
                    var ordinal = unchecked((ushort)(uint)NativeMethods.IMAGE_ORDINAL(readThunkRef));
                    writeFuncRef = functionCall.GetProcAddress(handle, ordinal);

                    if (writeFuncRef == Pointer.Zero && throwOnUnresolved)
                        throw new ModuleException("Import function not resolved: " + dllName + "!#" + ordinal);
                }
                else
                {
                    // import by name
                    var name = Marshal.PtrToStringAnsi(BaseAddress + readThunkRef + NativeOffsets.IMAGE_IMPORT_BY_NAME_Name);
                    writeFuncRef = functionCall.GetProcAddress(handle, name);

                    if (writeFuncRef == Pointer.Zero && throwOnUnresolved)
                        throw new ModuleException("Import function not resolved: " + dllName + "!" + name);
                }

                if (!writeFuncRef.IsInvalidHandle())
                    functionRef.Write(writeFuncRef);
            }

            return handle;
        }
    }
}
