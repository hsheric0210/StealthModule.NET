using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <typeparam name="TDelegate">The type of the delegate.</typeparam>
        /// <param name="functionName">The name of the function to be searched.</param>
        /// <returns>A delegate instance of type TDelegate</returns>
        public TDelegate GetExport<TDelegate>(string functionName) where TDelegate : class
        {
            if (!typeof(Delegate).IsAssignableFrom(typeof(TDelegate)))
                throw new ArgumentException(typeof(TDelegate).Name + " is not a delegate");
            var res = Marshal.GetDelegateForFunctionPointer(GetExportAddress(functionName), typeof(TDelegate)) as TDelegate;
            if (res == null)
                throw new ModuleException("Unable to get managed delegate");
            return res;
        }

        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <param name="functionName">The Name of the function to be searched.</param>
        /// <param name="delegateType">The type of the delegate to be returned.</param>
        /// <returns>A delegate instance that can be cast to the appropriate delegate type.</returns>
        public Delegate GetExport(string functionName, Type delegateType)
        {
            if (delegateType == null)
                throw new ArgumentNullException("delegateType");
            if (!typeof(Delegate).IsAssignableFrom(delegateType))
                throw new ArgumentException(delegateType.Name + " is not a delegate");
            var res = Marshal.GetDelegateForFunctionPointer(GetExportAddress(functionName), delegateType);
            if (res == null)
                throw new ModuleException("Unable to get managed delegate");
            return res;
        }

        public Pointer GetExportAddress(string functionName)
        {
            if (Disposed)
                throw new ObjectDisposedException("DLLFromMemory");
            if (string.IsNullOrEmpty(functionName))
                throw new ArgumentException("functionName");
            if (!IsDll)
                throw new InvalidOperationException("Loaded Module is not a DLL");
            if (!wasDllMainSuccessful)
                throw new InvalidOperationException("Dll is not initialized");

            var dataDirectoryAddress = ntHeadersAddress + (NativeOffsets.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? NativeOffsets64.IMAGE_OPTIONAL_HEADER_ExportTable : NativeOffsets32.IMAGE_OPTIONAL_HEADER_ExportTable));
            var dataDirectory = dataDirectoryAddress.Read<ImageDataDirectory>();
            if (dataDirectory.Size == 0)
                throw new ModuleException("Dll has no export table");

            var exportDirectoryAddress = moduleBaseAddress + dataDirectory.VirtualAddress;
            var exportDirectory = exportDirectoryAddress.Read<ImageExportDirectory>();
            if (exportDirectory.NumberOfFunctions == 0 || exportDirectory.NumberOfNames == 0)
                throw new ModuleException("Dll exports no functions");

            var nameAddress = moduleBaseAddress + exportDirectory.AddressOfNames;
            var ordinalAddress = moduleBaseAddress + exportDirectory.AddressOfNameOrdinals;
            for (var i = 0; i < exportDirectory.NumberOfNames; i++, nameAddress += sizeof(uint), ordinalAddress += sizeof(ushort))
            {
                var exportNameAddress = nameAddress.Read<uint>();
                var exportOrdinal = ordinalAddress.Read<ushort>();
                var exportName = Marshal.PtrToStringAnsi(moduleBaseAddress + exportNameAddress);
                if (exportName == functionName)
                {
                    if (exportOrdinal > exportDirectory.NumberOfFunctions)
                        throw new ModuleException("Invalid function ordinal");
                    var exportAddress = moduleBaseAddress + exportDirectory.AddressOfFunctions + (uint)(exportOrdinal * 4);
                    return moduleBaseAddress + exportAddress.Read<uint>();
                }
            }

            throw new ModuleException("Dll exports no function named " + functionName);
        }
    }
}
