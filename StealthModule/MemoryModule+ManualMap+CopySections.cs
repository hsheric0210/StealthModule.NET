using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        static void CopySections(ref ImageNtHeaders OrgNTHeaders, Pointer pCode, Pointer pNTHeaders, byte[] data)
        {
            var pSection = NativeMethods.IMAGE_FIRST_SECTION(pNTHeaders, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
            for (int i = 0; i < OrgNTHeaders.FileHeader.NumberOfSections; i++, pSection += NativeSizes.IMAGE_SECTION_HEADER)
            {
                ImageSectionHeader Section = pSection.Read<ImageSectionHeader>();
                if (Section.SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define uninitialized data
                    uint size = OrgNTHeaders.OptionalHeader.SectionAlignment;
                    if (size > 0)
                    {
                        IntPtr dest = NativeMethods.VirtualAlloc(pCode + Section.VirtualAddress, (UIntPtr)size, AllocationType.COMMIT, MemoryProtection.READWRITE);
                        if (dest == IntPtr.Zero)
                            throw new ModuleException("Unable to allocate memory");

                        // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                        dest = pCode + Section.VirtualAddress;

                        // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                        (pSection + NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));

                        NativeMethods.MemSet(dest, 0, (UIntPtr)size);
                    }

                    // section is empty
                    continue;
                }
                else
                {
                    // commit memory block and copy data from dll
                    IntPtr dest = NativeMethods.VirtualAlloc(pCode + Section.VirtualAddress, (UIntPtr)Section.SizeOfRawData, AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (dest == IntPtr.Zero)
                        throw new ModuleException("Out of memory");

                    // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                    dest = pCode + Section.VirtualAddress;
                    Marshal.Copy(data, checked((int)Section.PointerToRawData), dest, checked((int)Section.SizeOfRawData));

                    // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                    (pSection + NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));
                }
            }
        }

    }
}
