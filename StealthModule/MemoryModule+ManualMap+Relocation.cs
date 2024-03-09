using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        private static bool PerformBaseRelocation(ref ImageNtHeaders ntHeaders, Pointer moduleBaseAddress, Pointer delta)
        {
            if (ntHeaders.OptionalHeader.BaseRelocationTable.Size == 0)
                return delta == Pointer.Zero;

            for (var relocationAddress = moduleBaseAddress + ntHeaders.OptionalHeader.BaseRelocationTable.VirtualAddress; ;)
            {
                var relocation = relocationAddress.Read<ImageBaseRelocation>();
                if (relocation.VirtualAdress == 0)
                    break;

                var destAddress = moduleBaseAddress + relocation.VirtualAdress;
                var relocationInfoAddress = relocationAddress + NativeSizes.IMAGE_BASE_RELOCATION;
                var relocationCount = (relocation.SizeOfBlock - NativeSizes.IMAGE_BASE_RELOCATION) / 2;
                for (uint i = 0; i != relocationCount; i++, relocationInfoAddress += sizeof(ushort))
                {
                    var relocationInfo = relocationInfoAddress.Read<ushort>();
                    var type = (BasedRelocationType)(relocationInfo >> 12); // the upper 4 bits define the type of relocation
                    var offset = relocationInfo & 0xfff; // the lower 12 bits define the offset
                    var patchAddress = destAddress + offset;

                    switch (type)
                    {
                        case BasedRelocationType.IMAGE_REL_BASED_ABSOLUTE:
                            // skip relocation
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_HIGHLOW:
                            // change complete 32 bit address
                            var patchAddrHL = relocationInfoAddress.Read<int>();
                            patchAddrHL += (int)delta;
                            patchAddress.Write(patchAddrHL);
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_DIR64:
                            var patchAddr64 = relocationInfoAddress.Read<long>();
                            patchAddr64 += (long)delta;
                            patchAddress.Write(patchAddr64);
                            break;
                    }
                }

                // advance to next relocation block
                relocationAddress += relocation.SizeOfBlock;
            }

            return true;
        }
    }
}
