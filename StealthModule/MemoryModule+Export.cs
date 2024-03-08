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
    public partial class MemoryModule
    {

        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <typeparam name="TDelegate">The type of the delegate.</typeparam>
        /// <param name="funcName">The name of the function to be searched.</param>
        /// <returns>A delegate instance of type TDelegate</returns>
        public TDelegate GetExport<TDelegate>(string funcName) where TDelegate : class
        {
            if (!typeof(Delegate).IsAssignableFrom(typeof(TDelegate)))
                throw new ArgumentException(typeof(TDelegate).Name + " is not a delegate");
            if (!(Marshal.GetDelegateForFunctionPointer(WalkEDT(funcName), typeof(TDelegate)) is TDelegate res))
                throw new ModuleException("Unable to get managed delegate");

            return res;
        }

        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <param name="funcName">The Name of the function to be searched.</param>
        /// <param name="delegateType">The type of the delegate to be returned.</param>
        /// <returns>A delegate instance that can be cast to the appropriate delegate type.</returns>
        public Delegate GetExport(string funcName, Type delegateType)
        {
            if (delegateType == null)
                throw new ArgumentNullException(nameof(delegateType));
            if (!typeof(Delegate).IsAssignableFrom(delegateType))
                throw new ArgumentException(delegateType.Name + " is not a delegate");

            var res = Marshal.GetDelegateForFunctionPointer(WalkEDT(funcName), delegateType);
            if (res == null)
                throw new ModuleException("Unable to get managed delegate");

            return res;
        }

        internal Pointer WalkEDT(string funcName)
        {
            if (Disposed)
                throw new ObjectDisposedException(nameof(MemoryModule));
            if (string.IsNullOrEmpty(funcName))
                throw new ArgumentException(nameof(funcName));
            if (!IsDll)
                throw new InvalidOperationException("Loaded Module is not a DLL");
            if (!isInitialized)
                throw new InvalidOperationException("Dll is not initialized");

            if (moduleBase.Read<ushort>() != 0x5A04) // prevent calling WalkEDT() after erasing the PE header
                throw new ModuleException("Not a valid PE DOS header magic; Possibly your PE header is erased");

            var pDirectory = ntHeaders + NativeOffsets.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? NativeOffsets64.IMAGE_OPTIONAL_HEADER_ExportTable : NativeOffsets32.IMAGE_OPTIONAL_HEADER_ExportTable);
            var Directory = pDirectory.Read<IMAGE_DATA_DIRECTORY>();
            if (Directory.Size == 0)
                throw new ModuleException("Dll has no export table");

            var pExports = moduleBase + Directory.VirtualAddress;
            var Exports = pExports.Read<IMAGE_EXPORT_DIRECTORY>();
            if (Exports.NumberOfFunctions == 0 || Exports.NumberOfNames == 0)
                throw new ModuleException("Dll exports no functions");

            var pNameRef = moduleBase + Exports.AddressOfNames;
            var pOrdinal = moduleBase + Exports.AddressOfNameOrdinals;
            for (var i = 0; i < Exports.NumberOfNames; i++, pNameRef += sizeof(uint), pOrdinal += sizeof(ushort))
            {
                var NameRef = pNameRef.Read<uint>();
                var Ordinal = pOrdinal.Read<ushort>();
                var curFuncName = Marshal.PtrToStringAnsi(moduleBase + NameRef);
                if (curFuncName == funcName)
                {
                    if (Ordinal > Exports.NumberOfFunctions)
                        throw new ModuleException("Invalid function ordinal");

                    var pAddressOfFunction = moduleBase + Exports.AddressOfFunctions + (uint)(Ordinal * 4);
                    return moduleBase + pAddressOfFunction.Read<uint>();
                }
            }

            throw new ModuleException("Dll exports no function named " + funcName);
        }
    }
}
