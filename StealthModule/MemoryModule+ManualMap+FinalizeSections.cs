using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        static void FinalizeSections(ref ImageNtHeaders OrgNTHeaders, Pointer pCode, Pointer pNTHeaders, uint PageSize)
        {
            UIntPtr imageOffset = (Is64BitProcess ? (UIntPtr)(unchecked((ulong)(long)pCode) & 0xffffffff00000000) : UIntPtr.Zero);
            var pSection = NativeMethods.IMAGE_FIRST_SECTION(pNTHeaders, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
            ImageSectionHeader Section = pSection.Read<ImageSectionHeader>();
            SectionFinalizeData sectionData = new SectionFinalizeData();
            sectionData.Address = (Pointer.Zero + Section.PhysicalAddress) | imageOffset;
            sectionData.AlignedAddress = sectionData.Address.AlignDown((UIntPtr)PageSize);
            sectionData.Size = GetRealSectionSize(ref Section, ref OrgNTHeaders);
            sectionData.Characteristics = Section.Characteristics;
            sectionData.Last = false;
            pSection += NativeSizes.IMAGE_SECTION_HEADER;

            // loop through all sections and change access flags
            for (int i = 1; i < OrgNTHeaders.FileHeader.NumberOfSections; i++, pSection += NativeSizes.IMAGE_SECTION_HEADER)
            {
                Section = pSection.Read<ImageSectionHeader>();
                var sectionAddress = (Pointer.Zero + Section.PhysicalAddress) | imageOffset;
                var alignedAddress = sectionAddress.AlignDown((UIntPtr)PageSize);
                var sectionSize = GetRealSectionSize(ref Section, ref OrgNTHeaders);

                // Combine access flags of all sections that share a page
                // TODO(fancycode): We currently share flags of a trailing large section with the page of a first small section. This should be optimized.

                if (sectionData.AlignedAddress == alignedAddress || unchecked((ulong)(sectionData.Address + sectionData.Size)) > unchecked((ulong)alignedAddress))
                {
                    // Section shares page with previous
                    if ((Section.Characteristics & NativeMagics.IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.Characteristics & NativeMagics.IMAGE_SCN_MEM_DISCARDABLE) == 0)
                    {
                        sectionData.Characteristics = (sectionData.Characteristics | Section.Characteristics) & ~NativeMagics.IMAGE_SCN_MEM_DISCARDABLE;
                    }
                    else
                    {
                        sectionData.Characteristics |= Section.Characteristics;
                    }
                    sectionData.Size = sectionAddress + sectionSize - sectionData.Address;
                    continue;
                }

                FinalizeSection(sectionData, PageSize, OrgNTHeaders.OptionalHeader.SectionAlignment);

                sectionData.Address = sectionAddress;
                sectionData.AlignedAddress = alignedAddress;
                sectionData.Size = sectionSize;
                sectionData.Characteristics = Section.Characteristics;
            }
            sectionData.Last = true;
            FinalizeSection(sectionData, PageSize, OrgNTHeaders.OptionalHeader.SectionAlignment);
        }

        static void FinalizeSection(SectionFinalizeData SectionData, uint PageSize, uint SectionAlignment)
        {
            if (SectionData.Size == Pointer.Zero)
                return;

            if ((SectionData.Characteristics & NativeMagics.IMAGE_SCN_MEM_DISCARDABLE) > 0)
            {
                // section is not needed any more and can safely be freed
                if (SectionData.Address == SectionData.AlignedAddress &&
                    (SectionData.Last ||
                        SectionAlignment == PageSize ||
                        (unchecked((ulong)SectionData.Size) % PageSize) == 0)
                    )
                {
                    // Only allowed to decommit whole pages
                    NativeMethods.VirtualFree(SectionData.Address, SectionData.Size, AllocationType.DECOMMIT);
                }
                return;
            }

            // determine protection flags based on characteristics
            int readable = (SectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
            int writeable = (SectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;
            int executable = (SectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
            var protect = ProtectionFlags[executable, readable, writeable];
            if ((SectionData.Characteristics & NativeMagics.IMAGE_SCN_MEM_NOT_CACHED) > 0)
                protect |= MemoryProtection.NOCACHE;

            // change memory access flags
            MemoryProtection oldProtect;
            if (!NativeMethods.VirtualProtect(SectionData.Address, SectionData.Size, protect, out oldProtect))
                throw new ModuleException("Error protecting memory page");
        }

        static IntPtr GetRealSectionSize(ref ImageSectionHeader Section, ref ImageNtHeaders NTHeaders)
        {
            uint size = Section.SizeOfRawData;
            if (size == 0)
            {
                if ((Section.Characteristics & NativeMagics.IMAGE_SCN_CNT_INITIALIZED_DATA) > 0)
                {
                    size = NTHeaders.OptionalHeader.SizeOfInitializedData;
                }
                else if ((Section.Characteristics & NativeMagics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
                {
                    size = NTHeaders.OptionalHeader.SizeOfUninitializedData;
                }
            }
            return (IntPtr.Size == 8 ? (IntPtr)unchecked((long)size) : (IntPtr)unchecked((int)size));
        }

        // Protection flags for memory pages (Executable, Readable, Writeable)
        static readonly MemoryProtection[,,] ProtectionFlags = new MemoryProtection[2, 2, 2]
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

        struct SectionFinalizeData
        {
            internal Pointer Address;
            internal Pointer AlignedAddress;
            internal Pointer Size;
            internal uint Characteristics;
            internal bool Last;
        }
    }
}
