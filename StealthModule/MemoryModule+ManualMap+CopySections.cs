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

using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        private static void CopySections(Pointer moduleBase, ref IMAGE_NT_HEADERS ntHeadersData, Pointer ntHeadersAddress, byte[] data)
        {
            var sectionBase = NativeMethods.IMAGE_FIRST_SECTION(ntHeadersAddress, ntHeadersData.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i < ntHeadersData.FileHeader.NumberOfSections; i++, sectionBase += NativeSizes.IMAGE_SECTION_HEADER)
            {
                var sectionHeader = sectionBase.Read<IMAGE_SECTION_HEADER>();
                if (sectionHeader.SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define uninitialized data
                    var align = ntHeadersData.OptionalHeader.SectionAlignment;
                    if (align > 0)
                    {
                        var dest = NativeMethods.VirtualAlloc(moduleBase + sectionHeader.VirtualAddress, align, AllocationType.COMMIT, MemoryProtection.READWRITE);
                        if (dest == Pointer.Zero)
                            throw new ModuleException("Unable to allocate memory");

                        // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                        dest = moduleBase + sectionHeader.VirtualAddress;

                        // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                        (sectionBase + NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));

                        //NativeMethods.MemSet(dest, 0, (UIntPtr)size);
                        for (var j = 0; j < align; j++)
                            Marshal.WriteByte(dest, j, 0); // inefficient but at least it doesn't use any native function
                    }
                }
                else
                {
                    // commit memory block and copy data from dll
                    var dest = NativeMethods.VirtualAlloc(moduleBase + sectionHeader.VirtualAddress, sectionHeader.SizeOfRawData, AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (dest == Pointer.Zero)
                        throw new ModuleException("Out of memory");

                    // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                    dest = moduleBase + sectionHeader.VirtualAddress;
                    Marshal.Copy(data, checked((int)sectionHeader.PointerToRawData), dest, checked((int)sectionHeader.SizeOfRawData));

                    // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                    (sectionBase + NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));
                }
            }
        }
    }
}
