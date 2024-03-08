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
        private static bool PerformBaseRelocation(Pointer moduleBase, ref ImageNtHeaders ntHeaders, Pointer delta)
        {
            if (ntHeaders.OptionalHeader.BaseRelocationTable.Size == 0)
                return delta == Pointer.Zero;

            for (var relocationTableAddress = moduleBase + ntHeaders.OptionalHeader.BaseRelocationTable.VirtualAddress; ;)
            {
                var relocationTable = relocationTableAddress.Read<ImageBaseRelocation>();
                if (relocationTable.VirtualAdress == 0)
                    break;

                var relocationBaseAddress = moduleBase + relocationTable.VirtualAdress;
                var relocationInfoAddress = relocationTableAddress + NativeSizes.IMAGE_BASE_RELOCATION;
                var relocationCount = (relocationTable.SizeOfBlock - NativeSizes.IMAGE_BASE_RELOCATION) / 2;
                for (uint i = 0; i != relocationCount; i++, relocationInfoAddress += sizeof(ushort))
                {
                    var relocationInfos = (ushort)Marshal.PtrToStructure(relocationInfoAddress, typeof(ushort));
                    var relocationType = (BasedRelocationType)(relocationInfos >> 12); // the upper 4 bits define the type of relocation
                    var relocationOffset = relocationInfos & 0xfff; // the lower 12 bits define the offset
                    var patchAddress = relocationBaseAddress + relocationOffset;

                    switch (relocationType)
                    {
                        case BasedRelocationType.IMAGE_REL_BASED_ABSOLUTE:
                            // skip relocation
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_HIGHLOW:
                            // change complete 32 bit address
                            var patchAddressHighLow = (int)Marshal.PtrToStructure(patchAddress, typeof(int));
                            patchAddressHighLow += (int)delta;
                            Marshal.StructureToPtr(patchAddressHighLow, patchAddress, false);
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_DIR64:
                            var patchAddress64 = (long)Marshal.PtrToStructure(patchAddress, typeof(long));
                            patchAddress64 += (long)delta;
                            Marshal.StructureToPtr(patchAddress64, patchAddress, false);
                            break;
                    }
                }

                // advance to next relocation block
                relocationTableAddress += relocationTable.SizeOfBlock;
            }

            return true;
        }
    }
}
