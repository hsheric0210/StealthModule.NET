using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        static Pointer[] BuildImportTable(ref ImageNtHeaders OrgNTHeaders, Pointer pCode)
        {
            System.Collections.Generic.List<Pointer> ImportModules = new System.Collections.Generic.List<Pointer>();
            uint NumEntries = OrgNTHeaders.OptionalHeader.ImportTable.Size / NativeSizes.IMAGE_IMPORT_DESCRIPTOR;
            var pImportDesc = pCode + OrgNTHeaders.OptionalHeader.ImportTable.VirtualAddress;
            for (uint i = 0; i != NumEntries; i++, pImportDesc += NativeSizes.IMAGE_IMPORT_DESCRIPTOR)
            {
                ImageImportDescriptor ImportDesc = pImportDesc.Read<ImageImportDescriptor>();
                if (ImportDesc.Name == 0)
                    break;

                var handle = NativeMethods.LoadLibrary(pCode + ImportDesc.Name);
                if (handle.IsInvalidHandle())
                {
                    foreach (IntPtr m in ImportModules)
                        NativeMethods.FreeLibrary(m);
                    ImportModules.Clear();
                    throw new ModuleException("Can't load libary " + Marshal.PtrToStringAnsi(pCode + ImportDesc.Name));
                }
                ImportModules.Add(handle);

                Pointer pThunkRef, pFuncRef;
                if (ImportDesc.OriginalFirstThunk > 0)
                {
                    pThunkRef = pCode + ImportDesc.OriginalFirstThunk;
                    pFuncRef = pCode + ImportDesc.FirstThunk;
                }
                else
                {
                    // no hint table
                    pThunkRef = pCode + ImportDesc.FirstThunk;
                    pFuncRef = pCode + ImportDesc.FirstThunk;
                }
                for (int SzRef = IntPtr.Size; ; pThunkRef += SzRef, pFuncRef += SzRef)
                {
                    IntPtr ReadThunkRef = pThunkRef.Read<IntPtr>(), WriteFuncRef;
                    if (ReadThunkRef == IntPtr.Zero)
                        break;
                    if (NativeMethods.IMAGE_SNAP_BY_ORDINAL(ReadThunkRef))
                    {
                        WriteFuncRef = NativeMethods.GetProcAddress(handle, NativeMethods.IMAGE_ORDINAL(ReadThunkRef));
                    }
                    else
                    {
                        WriteFuncRef = NativeMethods.GetProcAddress(handle, (pCode + ReadThunkRef + NativeOffsets.IMAGE_IMPORT_BY_NAME_Name));
                    }
                    if (WriteFuncRef == IntPtr.Zero)
                        throw new ModuleException("Can't get adress for imported function");
                    pFuncRef.Write(WriteFuncRef);
                }
            }
            return (ImportModules.Count > 0 ? ImportModules.ToArray() : null);
        }

    }
}
