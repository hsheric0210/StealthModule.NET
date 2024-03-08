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
        private static Pointer AllocateAndCopyHeaders(Pointer moduleBase, ref ImageNtHeaders ntHeadersData, byte[] data)
        {
            // commit memory for headers
            var headers = NativeMethods.VirtualAlloc(moduleBase, ntHeadersData.OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (headers == Pointer.Zero)
                throw new OutOfMemoryException("Header memory");

            // copy PE header to code
            Marshal.Copy(data, 0, headers, (int)ntHeadersData.OptionalHeader.SizeOfHeaders);
            return headers;
        }

        private static Pointer AllocateModuleMemory(ref ImageNtHeaders ntHeadersData, uint alignedImageSize, Pointer preferredBaseAddress)
        {
            // reserve memory for image of library
            var mem = NativeMethods.VirtualAlloc(preferredBaseAddress, ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
            //pCode = Pointer.Zero; //test relocation with this

            // try to allocate memory at arbitrary position
            if (mem == Pointer.Zero)
                mem = NativeMethods.VirtualAlloc(Pointer.Zero, ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);

            if (mem == Pointer.Zero)
                throw new OutOfMemoryException("Module memory");

            if (Is64BitProcess && mem.SpanBoundary(alignedImageSize, 32))
            {
                // Memory block may not span 4 GB (32 bit) boundaries.
                var blockedMemory = new System.Collections.Generic.List<IntPtr>();
                while (mem.SpanBoundary(alignedImageSize, 32))
                {
                    blockedMemory.Add(mem);
                    mem = NativeMethods.VirtualAlloc(Pointer.Zero, alignedImageSize, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (mem == Pointer.Zero)
                        break;
                }
                foreach (var ptr in blockedMemory)
                    NativeMethods.VirtualFree(ptr, Pointer.Zero, AllocationType.RELEASE);
                if (mem == Pointer.Zero)
                    throw new OutOfMemoryException("Module memory block");
            }

            return mem;
        }
    }
}
