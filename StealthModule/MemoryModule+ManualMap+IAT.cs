using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        private static Pointer[] BuildImportTable(ref ImageNtHeaders ntHeadersData, Pointer moduleBaseAddress)
        {
            var importModules = new System.Collections.Generic.List<Pointer>();
            var numEntries = ntHeadersData.OptionalHeader.ImportTable.Size / NativeSizes.IMAGE_IMPORT_DESCRIPTOR;
            var importDescriptorAddress = moduleBaseAddress + ntHeadersData.OptionalHeader.ImportTable.VirtualAddress;
            for (uint i = 0; i != numEntries; i++, importDescriptorAddress += NativeSizes.IMAGE_IMPORT_DESCRIPTOR)
            {
                var importDescriptor = importDescriptorAddress.Read<ImageImportDescriptor>();
                if (importDescriptor.Name == 0)
                    break;

                var handle = NativeMethods.LoadLibrary(moduleBaseAddress + importDescriptor.Name);
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

                    writeFuncRef = NativeMethods.GetProcAddress(
                        handle,
                        NativeMethods.IMAGE_SNAP_BY_ORDINAL(readThunkRef)
                            ? NativeMethods.IMAGE_ORDINAL(readThunkRef)
                            : (moduleBaseAddress + readThunkRef + NativeOffsets.IMAGE_IMPORT_BY_NAME_Name));

                    if (writeFuncRef == Pointer.Zero)
                        throw new ModuleException("Can't get adress for imported function");

                    functionRef.Write(writeFuncRef);
                }
            }

            return importModules.ToArray();
        }
    }
}
