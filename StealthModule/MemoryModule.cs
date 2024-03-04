/*
 * DLLFromMemory.Net
 *
 * Load a native DLL from memory without the need to allow unsafe code
 *
 * Copyright (C) 2018 - 2019 by Bernhard Schelling
 *
 * Based on Memory Module.net 0.2
 * Copyright (C) 2012 - 2018 by Andreas Kanzler (andi_kanzler(at)gmx.de)
 * https://github.com/Scavanger/MemoryModule.net
 *
 * Based on Memory DLL loading code Version 0.0.4
 * Copyright (C) 2004 - 2015 by Joachim Bauch (mail(at)joachim-bauch.de)
 * https://github.com/fancycode/MemoryModule
 *
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.c
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004 - 2015
 * Joachim Bauch. All Rights Reserved.
 *
 * Portions created by Andreas Kanzler are Copyright (C) 2012 - 2018
 * Andreas Kanzler. All Rights Reserved.
 *
 * Portions created by Bernhard Schelling are Copyright (C) 2018 - 2019
 * Bernhard Schelling. All Rights Reserved.
 *
 */

using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule : IDisposable
    {
        public bool Disposed { get; private set; }
        public bool IsDll { get; private set; }

        private IntPtr moduleBase = IntPtr.Zero;
        private IntPtr ntHeader = IntPtr.Zero;
        private IntPtr[] importedModuleHandles;
        private bool isInitialized;
        private DllEntryDelegate dllEntry;
        private ExeEntryDelegate exeEntry;
        private bool isRelocated;

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate bool DllEntryDelegate(IntPtr hinstDLL, DllReason fdwReason, IntPtr lpReserved);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate int ExeEntryDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate void ImageTlsDelegate(IntPtr dllHandle, DllReason reason, IntPtr reserved);

        /// <summary>
        /// Loads a unmanged (native) DLL in the memory.
        /// </summary>
        /// <param name="data">Dll as a byte array</param>
        public MemoryModule(byte[] data)
        {
            NativeMethods.InitNatives();
            Disposed = false;
            if (data == null)
                throw new ArgumentNullException(nameof(data));
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
            if (!(Marshal.GetDelegateForFunctionPointer(GetPtrFromFuncName(funcName), typeof(TDelegate)) is TDelegate res))
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
                throw new ArgumentNullException(nameof(delegateType));
            if (!typeof(Delegate).IsAssignableFrom(delegateType))
                throw new ArgumentException(delegateType.Name + " is not a delegate");

            var res = Marshal.GetDelegateForFunctionPointer(GetPtrFromFuncName(funcName), delegateType);
            if (res == null)
                throw new ModuleException("Unable to get managed delegate");

            return res;
        }

        IntPtr GetPtrFromFuncName(string funcName)
        {
            if (Disposed)
                throw new ObjectDisposedException(nameof(MemoryModule));
            if (string.IsNullOrEmpty(funcName))
                throw new ArgumentException(nameof(funcName));
            if (!IsDll)
                throw new InvalidOperationException("Loaded Module is not a DLL");
            if (!isInitialized)
                throw new InvalidOperationException("Dll is not initialized");

            var pDirectory = ntHeader.Add(Of.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? Of64.IMAGE_OPTIONAL_HEADER_ExportTable : Of32.IMAGE_OPTIONAL_HEADER_ExportTable));
            var Directory = pDirectory.Read<IMAGE_DATA_DIRECTORY>();
            if (Directory.Size == 0)
                throw new ModuleException("Dll has no export table");

            var pExports = moduleBase.Add(Directory.VirtualAddress);
            var Exports = pExports.Read<IMAGE_EXPORT_DIRECTORY>();
            if (Exports.NumberOfFunctions == 0 || Exports.NumberOfNames == 0)
                throw new ModuleException("Dll exports no functions");

            var pNameRef = moduleBase.Add(Exports.AddressOfNames);
            var pOrdinal = moduleBase.Add(Exports.AddressOfNameOrdinals);
            for (var i = 0; i < Exports.NumberOfNames; i++, pNameRef = pNameRef.Add(sizeof(uint)), pOrdinal = pOrdinal.Add(sizeof(ushort)))
            {
                var NameRef = pNameRef.Read<uint>();
                var Ordinal = pOrdinal.Read<ushort>();
                var curFuncName = Marshal.PtrToStringAnsi(moduleBase.Add(NameRef));
                if (curFuncName == funcName)
                {
                    if (Ordinal > Exports.NumberOfFunctions)
                        throw new ModuleException("Invalid function ordinal");

                    var pAddressOfFunction = moduleBase.Add(Exports.AddressOfFunctions + (uint)(Ordinal * 4));
                    return moduleBase.Add(pAddressOfFunction.Read<uint>());
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
                throw new ObjectDisposedException(nameof(MemoryModule));

            if (IsDll || exeEntry == null || !isRelocated)
                throw new ModuleException("Unable to call entry point. Is loaded module a dll?");

            return exeEntry();
        }

        /// <summary>
        /// Check if the process runs in 64bit mode or in 32bit mode
        /// </summary>
        /// <returns>True if process is 64bit, false if it is 32bit</returns>
        public static bool Is64BitProcess => IntPtr.Size == 8;

        static uint GetMachineType() => IntPtr.Size == 8 ? Magic.IMAGE_FILE_MACHINE_AMD64 : Magic.IMAGE_FILE_MACHINE_I386;

        static uint AlignValueUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);

        public void Close() => ((IDisposable)this).Dispose();

        void IDisposable.Dispose()
        {
            Dispose();
            GC.SuppressFinalize(this);
        }

        public void Dispose()
        {
            if (isInitialized)
            {
                if (dllEntry != null)
                    dllEntry.Invoke(moduleBase, DllReason.DLL_PROCESS_DETACH, IntPtr.Zero);
                isInitialized = false;
            }

            if (importedModuleHandles != null)
            {
                foreach (var m in importedModuleHandles)
                    if (!m.IsInvalidHandle())
                        NativeMethods.FreeLibrary(m);
                importedModuleHandles = null;
            }

            if (moduleBase != IntPtr.Zero)
            {
                NativeMethods.VirtualFree(moduleBase, IntPtr.Zero, AllocationType.RELEASE);
                moduleBase = IntPtr.Zero;
                ntHeader = IntPtr.Zero;
            }

            Disposed = true;
        }

        // Protection flags for memory pages (Executable, Readable, Writeable)
        static readonly PageProtection[,,] ProtectionFlags = new PageProtection[2, 2, 2]
        {
        {
            // not executable
            { PageProtection.NOACCESS, PageProtection.WRITECOPY },
            { PageProtection.READONLY, PageProtection.READWRITE }
        },
        {
            // executable
            { PageProtection.EXECUTE, PageProtection.EXECUTE_WRITECOPY },
            { PageProtection.EXECUTE_READ, PageProtection.EXECUTE_READWRITE }
        }
        };
    }
}
