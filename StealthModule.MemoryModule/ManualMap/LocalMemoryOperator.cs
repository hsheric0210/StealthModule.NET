using System;
using System.Collections.Generic;
using System.Text;

namespace StealthModule.MemoryModule.ManualMap
{
    internal class LocalMemoryOperator : IMemoryOperator
    {
        public Pointer Allocate(Pointer desiredAddress, Pointer regionSize, AllocationType allocationType, MemoryProtection protection)
            => NativeMethods.AllocVirtualMemory(desiredAddress, regionSize, allocationType, protection);

        public bool Free(Pointer baseAddress, Pointer regionSize, AllocationType freeType)
            => NativeMethods.FreeVirtualMemory(baseAddress, regionSize, freeType);

        public bool Protect(Pointer baseAddress, Pointer regionSize, MemoryProtection protection, out MemoryProtection previousProtection)
            => NativeMethods.ProtectVirtualMemory(baseAddress, regionSize, protection, out previousProtection);
    }
}
