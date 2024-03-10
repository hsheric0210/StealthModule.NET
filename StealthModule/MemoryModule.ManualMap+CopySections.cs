﻿using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        private static void CopySections(ref ImageNtHeaders ntHeadersData, Pointer moduleBaseAddress, Pointer ntHeadersAddress, byte[] data, bool stomping)
        {
            var sectionOffset = NativeMethods.IMAGE_FIRST_SECTION(ntHeadersAddress, ntHeadersData.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i < ntHeadersData.FileHeader.NumberOfSections; i++, sectionOffset += NativeSizes.IMAGE_SECTION_HEADER)
            {
                var sectionHeader = sectionOffset.Read<ImageSectionHeader>();
                if (sectionHeader.SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define uninitialized data
                    var size = ntHeadersData.OptionalHeader.SectionAlignment;
                    if (size > 0)
                    {
                        var dest = ConditionalVirtualAlloc(moduleBaseAddress + sectionHeader.VirtualAddress, (Pointer)size, AllocationType.COMMIT, MemoryProtection.READWRITE, stomping);
                        if (dest == Pointer.Zero)
                            throw new ModuleException("Unable to allocate memory");

                        // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                        dest = moduleBaseAddress + sectionHeader.VirtualAddress;

                        // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                        (sectionOffset + NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));

                        var zeros = new byte[size];
                        Marshal.Copy(zeros, 0, dest, unchecked((int)size));
                    }

                    // section is empty
                }
                else
                {
                    // commit memory block and copy data from dll
                    var dest = ConditionalVirtualAlloc(moduleBaseAddress + sectionHeader.VirtualAddress, (Pointer)sectionHeader.SizeOfRawData, AllocationType.COMMIT, MemoryProtection.READWRITE, stomping);
                    if (dest == Pointer.Zero)
                        throw new ModuleException("Out of memory");

                    // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                    dest = moduleBaseAddress + sectionHeader.VirtualAddress;
                    var offset = checked((int)sectionHeader.PointerToRawData);
                    Marshal.Copy(data, offset, dest, checked((int)sectionHeader.SizeOfRawData));

                    // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                    (sectionOffset + NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));
                }
            }
        }
    }
}