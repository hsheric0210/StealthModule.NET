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
        private static Pointer[] BuildIDT(Pointer moduleBase, ref IMAGE_NT_HEADERS ntHeaders)
        {
            var importModules = new System.Collections.Generic.List<Pointer>();
            var entryCount = ntHeaders.OptionalHeader.ImportTable.Size / Sz.IMAGE_IMPORT_DESCRIPTOR;
            var importDescriptorTableAddress = moduleBase + ntHeaders.OptionalHeader.ImportTable.VirtualAddress;
            for (uint i = 0; i != entryCount; i++, importDescriptorTableAddress += Sz.IMAGE_IMPORT_DESCRIPTOR)
            {
                var importDescriptor = importDescriptorTableAddress.Read<IMAGE_IMPORT_DESCRIPTOR>();
                if (importDescriptor.Name == 0)
                    break;

                var importModule = NativeMethods.LoadLibrary(moduleBase + importDescriptor.Name);
                if (importModule.IsInvalidHandle())
                {
                    foreach (var m in importModules)
                        NativeMethods.FreeLibrary(m);
                    importModules.Clear();
                    throw new ModuleException("Can't load libary " + Marshal.PtrToStringAnsi(moduleBase + importDescriptor.Name));
                }

                importModules.Add(importModule);

                Pointer thunkAddress, functionAddress;
                if (importDescriptor.OriginalFirstThunk > 0)
                {
                    thunkAddress = moduleBase + importDescriptor.OriginalFirstThunk;
                    functionAddress = moduleBase + importDescriptor.FirstThunk;
                }
                else
                {
                    // no hint table
                    thunkAddress = functionAddress = moduleBase + importDescriptor.FirstThunk;
                }

                for (var pointerSize = IntPtr.Size; ; thunkAddress += pointerSize, functionAddress += pointerSize)
                {
                    Pointer ReadThunkRef = thunkAddress.ReadPointer(), WriteFuncRef;
                    if (ReadThunkRef == Pointer.Zero)
                        break;

                    if (NativeMethods.IMAGE_SNAP_BY_ORDINAL(ReadThunkRef))
                        WriteFuncRef = NativeMethods.GetProcAddress(importModule, NativeMethods.IMAGE_ORDINAL(ReadThunkRef));
                    else
                        WriteFuncRef = NativeMethods.GetProcAddress(importModule, moduleBase + ReadThunkRef + Of.IMAGE_IMPORT_BY_NAME_Name);

                    if (WriteFuncRef == Pointer.Zero)
                        throw new ModuleException("Can't get address for imported function");

                    functionAddress.Write(WriteFuncRef);
                }
            }

            return importModules.ToArray();
        }
    }
}
