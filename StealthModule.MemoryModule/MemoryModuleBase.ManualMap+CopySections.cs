using System.Runtime.InteropServices;
using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule
{
    public partial class MemoryModuleBase
    {
        protected virtual void CopySections(ref byte[] data)
        {
            var sectionOffset = NativeMethods.IMAGE_FIRST_SECTION(ntHeadersAddress, ntHeaders.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++, sectionOffset += NativeSizes.IMAGE_SECTION_HEADER)
            {
                var sectionHeader = sectionOffset.Read<ImageSectionHeader>();
                if (sectionHeader.SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define uninitialized data
                    var size = ntHeaders.OptionalHeader.SectionAlignment;
                    if (size > 0)
                        FillSectionAlignment(sectionOffset, sectionHeader, size);

                    // section is empty
                }
                else
                {
                    CopySingleSection(sectionOffset, sectionHeader, ref data);
                }
            }
        }

        private void CopySingleSection(Pointer sectionOffset, ImageSectionHeader sectionHeader, ref byte[] data)
        {
            var dest = memoryOp.Allocate(BaseAddress + sectionHeader.VirtualAddress, (Pointer)sectionHeader.SizeOfRawData, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (dest == Pointer.Zero)
                throw new ModuleException("Out of memory");

            // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
            dest = BaseAddress + sectionHeader.VirtualAddress;
            var offset = checked((int)sectionHeader.PointerToRawData);
            Marshal.Copy(data, offset, dest, checked((int)sectionHeader.SizeOfRawData));

            // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
            (sectionOffset + NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));
        }

        protected virtual void FillSectionAlignment(Pointer sectionOffset, ImageSectionHeader sectionHeader, uint sectionSize)
        {
            var dest = memoryOp.Allocate(BaseAddress + sectionHeader.VirtualAddress, (Pointer)sectionSize, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (dest == Pointer.Zero)
                throw new ModuleException("Unable to allocate memory");

            // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
            dest = BaseAddress + sectionHeader.VirtualAddress;

            // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
            (sectionOffset + NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));

            var zeros = new byte[sectionSize];
            Marshal.Copy(zeros, 0, dest, unchecked((int)sectionSize));
        }
    }
}
