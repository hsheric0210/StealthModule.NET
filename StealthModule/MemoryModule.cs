using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule : IDisposable
    {
        public bool Disposed { get; private set; }
        public bool IsDll { get; private set; }

        Pointer pCode = Pointer.Zero;
        Pointer pNTHeaders = Pointer.Zero;
        Pointer[] ImportModules;
        bool _initialized = false;
        DllEntryDelegate _dllEntry = null;
        ExeEntryDelegate _exeEntry = null;
        bool _isRelocated = false;

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate bool DllEntryDelegate(IntPtr hinstDLL, DllReason fdwReason, IntPtr lpReserved);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate int ExeEntryDelegate();

        /// <summary>
        /// Loads a unmanged (native) DLL in the memory.
        /// </summary>
        /// <param name="data">Dll as a byte array</param>
        public MemoryModule(byte[] data)
        {
            Disposed = false;
            if (data == null)
                throw new ArgumentNullException("data");
            MemoryLoadLibrary(data);
        }

        ~MemoryModule()
        {
            Dispose();
        }

        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <typeparam name="TDelegate">The type of the delegate.</typeparam>
        /// <param name="funcName">The name of the function to be searched.</param>
        /// <returns>A delegate instance of type TDelegate</returns>
        public TDelegate GetDelegateFromFuncName<TDelegate>(string funcName) where TDelegate : class
        {
            if (!typeof(Delegate).IsAssignableFrom(typeof(TDelegate)))
                throw new ArgumentException(typeof(TDelegate).Name + " is not a delegate");
            var res = Marshal.GetDelegateForFunctionPointer(GetPtrFromFuncName(funcName), typeof(TDelegate)) as TDelegate;
            if (res == null)
                throw new ModuleException("Unable to get managed delegate");
            return res;
        }

        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <param name="funcName">The Name of the function to be searched.</param>
        /// <param name="delegateType">The type of the delegate to be returned.</param>
        /// <returns>A delegate instance that can be cast to the appropriate delegate type.</returns>
        public Delegate GetDelegateFromFuncName(string funcName, Type delegateType)
        {
            if (delegateType == null)
                throw new ArgumentNullException("delegateType");
            if (!typeof(Delegate).IsAssignableFrom(delegateType))
                throw new ArgumentException(delegateType.Name + " is not a delegate");
            var res = Marshal.GetDelegateForFunctionPointer(GetPtrFromFuncName(funcName), delegateType);
            if (res == null)
                throw new ModuleException("Unable to get managed delegate");
            return res;
        }

        public Pointer GetPtrFromFuncName(string funcName)
        {
            if (Disposed)
                throw new ObjectDisposedException("DLLFromMemory");
            if (string.IsNullOrEmpty(funcName))
                throw new ArgumentException("funcName");
            if (!IsDll)
                throw new InvalidOperationException("Loaded Module is not a DLL");
            if (!_initialized)
                throw new InvalidOperationException("Dll is not initialized");

            var pDirectory = pNTHeaders + (NativeOffsets.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? NativeOffsets64.IMAGE_OPTIONAL_HEADER_ExportTable : NativeOffsets32.IMAGE_OPTIONAL_HEADER_ExportTable));
            var Directory = pDirectory.Read<ImageDataDirectory>();
            if (Directory.Size == 0)
                throw new ModuleException("Dll has no export table");

            var pExports = pCode + Directory.VirtualAddress;
            var Exports = pExports.Read<ImageExportDirectory>();
            if (Exports.NumberOfFunctions == 0 || Exports.NumberOfNames == 0)
                throw new ModuleException("Dll exports no functions");

            var pNameRef = pCode + Exports.AddressOfNames;
            var pOrdinal = pCode + Exports.AddressOfNameOrdinals;
            for (var i = 0; i < Exports.NumberOfNames; i++, pNameRef += sizeof(uint), pOrdinal += sizeof(ushort))
            {
                var NameRef = pNameRef.Read<uint>();
                var Ordinal = pOrdinal.Read<ushort>();
                var curFuncName = Marshal.PtrToStringAnsi(pCode + NameRef);
                if (curFuncName == funcName)
                {
                    if (Ordinal > Exports.NumberOfFunctions)
                        throw new ModuleException("Invalid function ordinal");
                    var pAddressOfFunction = pCode + Exports.AddressOfFunctions + (uint)(Ordinal * 4);
                    return pCode + pAddressOfFunction.Read<uint>();
                }
            }

            throw new ModuleException("Dll exports no function named " + funcName);
        }

        /// <summary>
        /// Call entry point of executable.
        /// </summary>
        /// <returns>Exitcode of executable</returns>
        public int MemoryCallEntryPoint()
        {
            if (Disposed)
                throw new ObjectDisposedException("DLLFromMemory");
            if (IsDll || _exeEntry == null || !_isRelocated)
                throw new ModuleException("Unable to call entry point. Is loaded module a dll?");
            return _exeEntry();
        }

        /// <summary>
        /// Check if the process runs in 64bit mode or in 32bit mode
        /// </summary>
        /// <returns>True if process is 64bit, false if it is 32bit</returns>
        public static bool Is64BitProcess => Pointer.Is64Bit;

        public void Close() => ((IDisposable)this).Dispose();

        void IDisposable.Dispose()
        {
            Dispose();
            GC.SuppressFinalize(this);
        }

        public void Dispose()
        {
            if (_initialized)
            {
                if (_dllEntry != null)
                    _dllEntry.Invoke(pCode, DllReason.DLL_PROCESS_DETACH, IntPtr.Zero);
                _initialized = false;
            }

            if (ImportModules != null)
            {
                foreach (var m in ImportModules)
                    if (!m.IsInvalidHandle())
                        NativeMethods.FreeLibrary(m);
                ImportModules = null;
            }

            if (pCode != Pointer.Zero)
            {
                NativeMethods.VirtualFree(pCode, IntPtr.Zero, AllocationType.RELEASE);
                pCode = Pointer.Zero;
                pNTHeaders = Pointer.Zero;
            }

            Disposed = true;
        }
    }
}
