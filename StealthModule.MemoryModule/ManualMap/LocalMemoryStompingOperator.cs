﻿using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule.ManualMap
{
    internal class LocalMemoryStompingOperator : IMemoryOperator
    {
        public Pointer Allocate(Pointer desiredAddress, Pointer regionSize, AllocationType allocationType, MemoryProtection protection)
            => desiredAddress; // All addresses are already allocated

        public bool Free(Pointer baseAddress, Pointer regionSize, AllocationType freeType)
            => NativeMethods.FreeVirtualMemory(baseAddress, regionSize, freeType);

        public bool Protect(Pointer baseAddress, Pointer regionSize, MemoryProtection protection, out MemoryProtection previousProtection)
            => NativeMethods.ProtectVirtualMemory(baseAddress, regionSize, protection, out previousProtection);
    }
}
