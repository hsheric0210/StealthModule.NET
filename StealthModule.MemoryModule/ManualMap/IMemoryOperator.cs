using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule.ManualMap
{
    public interface IMemoryOperator
    {
        Pointer Allocate(Pointer desiredAddress, Pointer regionSize, AllocationType allocationType, MemoryProtection protection);

        bool Protect(Pointer baseAddress, Pointer regionSize, MemoryProtection protection, out MemoryProtection previousProtection);

        bool Free(Pointer baseAddress, Pointer regionSize, AllocationType freeType);
    }
}
