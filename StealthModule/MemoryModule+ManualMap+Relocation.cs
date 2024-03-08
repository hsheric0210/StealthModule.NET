using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        static bool PerformBaseRelocation(ref ImageNtHeaders OrgNTHeaders, Pointer pCode, Pointer delta)
        {
            if (OrgNTHeaders.OptionalHeader.BaseRelocationTable.Size == 0)
                return delta == Pointer.Zero;

            for (var pRelocation = pCode + OrgNTHeaders.OptionalHeader.BaseRelocationTable.VirtualAddress; ;)
            {
                var Relocation = pRelocation.Read<ImageBaseRelocation>();
                if (Relocation.VirtualAdress == 0)
                    break;

                var pDest = pCode + Relocation.VirtualAdress;
                var pRelInfo = pRelocation + NativeSizes.IMAGE_BASE_RELOCATION;
                var RelCount = (Relocation.SizeOfBlock - NativeSizes.IMAGE_BASE_RELOCATION) / 2;
                for (uint i = 0; i != RelCount; i++, pRelInfo += sizeof(ushort))
                {
                    var relInfo = (ushort)Marshal.PtrToStructure(pRelInfo, typeof(ushort));
                    var type = (BasedRelocationType)(relInfo >> 12); // the upper 4 bits define the type of relocation
                    var offset = relInfo & 0xfff; // the lower 12 bits define the offset
                    var pPatchAddr = pDest + offset;

                    switch (type)
                    {
                        case BasedRelocationType.IMAGE_REL_BASED_ABSOLUTE:
                            // skip relocation
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_HIGHLOW:
                            // change complete 32 bit address
                            var patchAddrHL = (int)Marshal.PtrToStructure(pPatchAddr, typeof(int));
                            patchAddrHL += (int)delta;
                            Marshal.StructureToPtr(patchAddrHL, pPatchAddr, false);
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_DIR64:
                            var patchAddr64 = (long)Marshal.PtrToStructure(pPatchAddr, typeof(long));
                            patchAddr64 += (long)delta;
                            Marshal.StructureToPtr(patchAddr64, pPatchAddr, false);
                            break;
                    }
                }

                // advance to next relocation block
                pRelocation += Relocation.SizeOfBlock;
            }
            return true;
        }

    }
}
