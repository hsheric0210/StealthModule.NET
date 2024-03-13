using System;

namespace StealthModule
{
    public partial class MemoryModuleBase
    {
        protected virtual void FinalizeSections(uint PageSize)
        {
            var imageOffset = Is64BitProcess ? (UIntPtr)(((ulong)BaseAddress) & 0xffffffff00000000) : UIntPtr.Zero;
            var sectionOffset = NativeMethods.IMAGE_FIRST_SECTION(ntHeadersAddress, ntHeaders.FileHeader.SizeOfOptionalHeader);
            var sectionHeader = sectionOffset.Read<ImageSectionHeader>();
            var sectionAddress = (Pointer.Zero + sectionHeader.PhysicalAddress) | imageOffset;
            var sectionData = new SectionFinalizeData
            {
                Address = sectionAddress,
                AlignedAddress = sectionAddress.AlignDown((UIntPtr)PageSize),
                Size = GetRealSectionSize(ref sectionHeader),
                Characteristics = sectionHeader.Characteristics,
                Last = false
            };

            sectionOffset += NativeSizes.IMAGE_SECTION_HEADER;

            // loop through all sections and change access flags
            for (var i = 1; i < ntHeaders.FileHeader.NumberOfSections; i++, sectionOffset += NativeSizes.IMAGE_SECTION_HEADER)
            {
                sectionHeader = sectionOffset.Read<ImageSectionHeader>();
                sectionAddress = (Pointer.Zero + sectionHeader.PhysicalAddress) | imageOffset;
                var alignedAddress = sectionAddress.AlignDown((UIntPtr)PageSize);
                var sectionSize = GetRealSectionSize(ref sectionHeader);

                // Combine access flags of all sections that share a page
                // TODO(fancycode): We currently share flags of a trailing large section with the page of a first small section. This should be optimized.

                if (sectionData.AlignedAddress == alignedAddress || unchecked((ulong)(sectionData.Address + sectionData.Size)) > unchecked((ulong)alignedAddress))
                {
                    // Section shares page with previous
                    if ((sectionHeader.Characteristics & NativeMagics.IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.Characteristics & NativeMagics.IMAGE_SCN_MEM_DISCARDABLE) == 0)
                        sectionData.Characteristics = (sectionData.Characteristics | sectionHeader.Characteristics) & ~NativeMagics.IMAGE_SCN_MEM_DISCARDABLE;
                    else
                        sectionData.Characteristics |= sectionHeader.Characteristics;

                    sectionData.Size = sectionAddress + sectionSize - sectionData.Address;
                    continue;
                }

                FinalizeSection(sectionData, PageSize, ntHeaders.OptionalHeader.SectionAlignment);

                sectionData.Address = sectionAddress;
                sectionData.AlignedAddress = alignedAddress;
                sectionData.Size = sectionSize;
                sectionData.Characteristics = sectionHeader.Characteristics;
            }

            sectionData.Last = true;
            FinalizeSection(sectionData, PageSize, ntHeaders.OptionalHeader.SectionAlignment);
        }

        protected virtual void FinalizeSection(SectionFinalizeData sectionData, uint pageSize, uint sectionAlignment)
        {
            if (sectionData.Size == Pointer.Zero)
                return;

            if ((sectionData.Characteristics & NativeMagics.IMAGE_SCN_MEM_DISCARDABLE) > 0)
            {
                // section is not needed any more and can safely be freed
                if (sectionData.Address == sectionData.AlignedAddress && (sectionData.Last || sectionAlignment == pageSize || (ulong)sectionData.Size % pageSize == 0))
                {
                    // Only allowed to decommit whole pages
                    NativeMethods.FreeVirtualMemory(sectionData.Address, sectionData.Size, AllocationType.DECOMMIT);
                }

                return;
            }

            // determine protection flags based on characteristics
            var readable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
            var writeable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;
            var executable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
            var protect = ProtectionFlags[executable, readable, writeable];
            if ((sectionData.Characteristics & NativeMagics.IMAGE_SCN_MEM_NOT_CACHED) > 0)
                protect |= MemoryProtection.NOCACHE;

            // change memory access flags
            if (!NativeMethods.ProtectVirtualMemory(sectionData.Address, sectionData.Size, protect))
                throw new ModuleException("Error protecting memory page");
        }

        protected virtual Pointer GetRealSectionSize(ref ImageSectionHeader section)
        {
            var size = section.SizeOfRawData;
            if (size == 0)
            {
                if ((section.Characteristics & NativeMagics.IMAGE_SCN_CNT_INITIALIZED_DATA) > 0)
                    size = ntHeaders.OptionalHeader.SizeOfInitializedData;
                else if ((section.Characteristics & NativeMagics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
                    size = ntHeaders.OptionalHeader.SizeOfUninitializedData;
            }

            return (Pointer)size;
        }

        // Protection flags for memory pages (Executable, Readable, Writeable)
        protected readonly MemoryProtection[,,] ProtectionFlags = new MemoryProtection[2, 2, 2]
        {
        {
            // not executable
            { MemoryProtection.NOACCESS, MemoryProtection.WRITECOPY },
            { MemoryProtection.READONLY, MemoryProtection.READWRITE }
        },
        {
            // executable
            { MemoryProtection.EXECUTE, MemoryProtection.EXECUTE_WRITECOPY },
            { MemoryProtection.EXECUTE_READ, MemoryProtection.EXECUTE_READWRITE }
        }
        };

        protected struct SectionFinalizeData
        {
            internal Pointer Address;
            internal Pointer AlignedAddress;
            internal Pointer Size;
            internal uint Characteristics;
            internal bool Last;
        }
    }
}
