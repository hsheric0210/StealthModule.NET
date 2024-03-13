namespace StealthModule.MemoryModule
{
    public partial class MemoryModuleBase
    {
        protected virtual bool PerformBaseRelocation(Pointer addressDelta)
        {
            if (ntHeaders.OptionalHeader.BaseRelocationTable.Size == 0) // Relocation table is empty
                return addressDelta == Pointer.Zero; // Don't need to relocate

            for (var relocationAddress = BaseAddress + ntHeaders.OptionalHeader.BaseRelocationTable.VirtualAddress; ;)
            {
                var relocation = relocationAddress.Read<ImageBaseRelocation>();
                if (relocation.VirtualAdress == 0)
                    break;

                ProcessSingleRelocation(relocationAddress, relocation, addressDelta);

                // advance to next relocation block
                relocationAddress += relocation.SizeOfBlock;
            }

            return true;
        }

        protected virtual void ProcessSingleRelocation(Pointer relocationAddress, ImageBaseRelocation relocation, Pointer addressDelta)
        {
            var destAddress = BaseAddress + relocation.VirtualAdress;

            var relocationInfoAddress = relocationAddress + NativeSizes.IMAGE_BASE_RELOCATION;
            var relocationCount = (relocation.SizeOfBlock - NativeSizes.IMAGE_BASE_RELOCATION) / 2;
            for (uint i = 0; i != relocationCount; i++, relocationInfoAddress += sizeof(ushort))
            {
                var relocationInfo = relocationInfoAddress.Read<ushort>();
                ProcessSingleRelocationInfo(destAddress, relocationInfo, addressDelta);
            }
        }

        protected virtual void ProcessSingleRelocationInfo(Pointer destAddress, ushort relocationInfo, Pointer addressDelta)
        {
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
                    var patchAddrHL = patchAddress.Read<int>();
                    patchAddrHL += (int)addressDelta;
                    patchAddress.Write(patchAddrHL);
                    break;
                case BasedRelocationType.IMAGE_REL_BASED_DIR64:
                    var patchAddr64 = patchAddress.Read<long>();
                    patchAddr64 += (long)addressDelta;
                    patchAddress.Write(patchAddr64);
                    break;
            }
        }
    }
}
