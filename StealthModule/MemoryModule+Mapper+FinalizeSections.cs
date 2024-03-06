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
        private static void FinalizeSections(Pointer moduleBase, ref IMAGE_NT_HEADERS ntHeadersData, Pointer ntHeadersAddress, uint pageSize)
        {
            var imageOffset = Is64BitProcess ? ((ulong)moduleBase & 0xffffffff00000000) : Pointer.Zero;
            var sectionHeaderAddress = NativeMethods.IMAGE_FIRST_SECTION(ntHeadersAddress, ntHeadersData.FileHeader.SizeOfOptionalHeader);
            var sectionHeader = sectionHeaderAddress.Read<IMAGE_SECTION_HEADER>();

            var sectionData = new SectionFinalizeData();
            sectionData.Address = sectionHeader.PhysicalAddress | imageOffset;
            sectionData.AlignedAddress = sectionData.Address.AlignDown((UIntPtr)pageSize);
            sectionData.Size = GetRealSectionSize(ref sectionHeader, ref ntHeadersData);
            sectionData.Characteristics = sectionHeader.Characteristics;
            sectionData.Last = false;

            sectionHeaderAddress += Sz.IMAGE_SECTION_HEADER;

            // loop through all sections and change access flags
            for (var i = 1; i < ntHeadersData.FileHeader.NumberOfSections; i++, sectionHeaderAddress += Sz.IMAGE_SECTION_HEADER)
            {
                sectionHeader = sectionHeaderAddress.Read<IMAGE_SECTION_HEADER>();
                var sectionAddress = sectionHeader.PhysicalAddress | imageOffset;
                var alignedAddress = sectionAddress.AlignDown((UIntPtr)pageSize);
                var sectionSize = GetRealSectionSize(ref sectionHeader, ref ntHeadersData);

                // Combine access flags of all sections that share a page
                // TODO(fancycode): We currently share flags of a trailing large section with the page of a first small section. This should be optimized.
                var a = sectionData.Address + sectionData.Size;
                ulong b = (ulong)a, c = unchecked((ulong)alignedAddress);

                if (sectionData.AlignedAddress == alignedAddress || (ulong)(sectionData.Address + sectionData.Size) > (ulong)alignedAddress)
                {
                    // Section shares page with previous

                    if ((sectionHeader.Characteristics & Magic.IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.Characteristics & Magic.IMAGE_SCN_MEM_DISCARDABLE) == 0)
                        sectionData.Characteristics = (sectionData.Characteristics | sectionHeader.Characteristics) & ~Magic.IMAGE_SCN_MEM_DISCARDABLE;
                    else
                        sectionData.Characteristics |= sectionHeader.Characteristics;

                    sectionData.Size = sectionAddress + sectionSize - sectionData.Address;
                    continue;
                }

                FinalizeSection(sectionData, pageSize, ntHeadersData.OptionalHeader.SectionAlignment);

                sectionData.Address = sectionAddress;
                sectionData.AlignedAddress = alignedAddress;
                sectionData.Size = sectionSize;
                sectionData.Characteristics = sectionHeader.Characteristics;
            }

            sectionData.Last = true;
            FinalizeSection(sectionData, pageSize, ntHeadersData.OptionalHeader.SectionAlignment);
        }

        private static void FinalizeSection(SectionFinalizeData sectionData, uint pageSize, uint sectionAlignment)
        {
            if (sectionData.Size == Pointer.Zero)
                return;

            if ((sectionData.Characteristics & Magic.IMAGE_SCN_MEM_DISCARDABLE) > 0)
            {
                // section is not needed any more and can safely be freed
                if (sectionData.Address == sectionData.AlignedAddress && (sectionData.Last || sectionAlignment == pageSize || (ulong)sectionData.Size % pageSize == 0))
                {
                    // Only allowed to decommit whole pages
                    NativeMethods.VirtualFree(sectionData.Address, sectionData.Size, AllocationType.DECOMMIT);
                }
                return;
            }

            // determine protection flags based on characteristics
            var readable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
            var writeable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;
            var executable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
            var protect = (uint)ProtectionFlags[executable, readable, writeable];
            if ((sectionData.Characteristics & Magic.IMAGE_SCN_MEM_NOT_CACHED) > 0)
                protect |= Magic.PAGE_NOCACHE;

            // change memory access flags
            if (!NativeMethods.VirtualProtect(sectionData.Address, sectionData.Size, protect, out var oldProtect))
                throw new ModuleException("Error protecting memory page");
        }

        private static IntPtr GetRealSectionSize(ref IMAGE_SECTION_HEADER sectionHeader, ref IMAGE_NT_HEADERS ntHeaders)
        {
            var size = sectionHeader.SizeOfRawData;
            if (size == 0)
            {
                if ((sectionHeader.Characteristics & Magic.IMAGE_SCN_CNT_INITIALIZED_DATA) > 0)
                    size = ntHeaders.OptionalHeader.SizeOfInitializedData;
                else if ((sectionHeader.Characteristics & Magic.IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
                    size = ntHeaders.OptionalHeader.SizeOfUninitializedData;
            }
            return IntPtr.Size == 8 ? (IntPtr)unchecked((long)size) : (IntPtr)unchecked((int)size);
        }
    }
}
