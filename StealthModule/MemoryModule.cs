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

        /// <summary>
        /// Check if the process runs in 64bit mode or in 32bit mode
        /// </summary>
        /// <returns>True if process is 64bit, false if it is 32bit</returns>
        public static bool Is64BitProcess => IntPtr.Size == 8;

        private Pointer moduleBase = Pointer.Zero;
        private Pointer ntHeaders = Pointer.Zero;
        private Pointer[] importedModuleHandles;
        private bool isInitialized;
        private DllEntryDelegate dllEntry;
        private ExeEntryDelegate exeEntry;
        private bool isRelocated;

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
            NativeMethods.InitNatives();
            Disposed = false;
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            ManualMap(data);
        }

        ~MemoryModule()
        {
            Dispose();
        }

        /// <summary>
        /// Call entry point of executable.
        /// </summary>
        /// <returns>Exitcode of executable</returns>
        public int CallEntryPoint()
        {
            if (Disposed)
                throw new ObjectDisposedException(nameof(MemoryModule));

            if (IsDll || exeEntry == null || !isRelocated)
                throw new ModuleException("Unable to call entry point. Is loaded module a dll?");

            return exeEntry();
        }

        // Cleanup

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
                dllEntry?.Invoke(moduleBase, DllReason.DLL_PROCESS_DETACH, Pointer.Zero);
                isInitialized = false;
            }

            foreach (var m in importedModuleHandles)
            {
                if (!m.IsInvalidHandle())
                    NativeMethods.FreeLibrary(m);
            }

            importedModuleHandles = null;

            if (moduleBase != Pointer.Zero)
            {
                NativeMethods.VirtualFree(moduleBase, Pointer.Zero, AllocationType.RELEASE);
                moduleBase = Pointer.Zero;
                ntHeaders = Pointer.Zero;
            }

            Disposed = true;
        }
    }
}
