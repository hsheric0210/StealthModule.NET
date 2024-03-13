using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule
{
    public partial class MemoryModuleBase
    {
        protected virtual Pointer AllocateBaseMemory(Pointer desiredAddress, uint regionSize)
        {
            // reserve memory for image of library
            var memory = NativeMethods.AllocVirtualMemory(desiredAddress, (Pointer)ntHeaders.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
            //pCode = IntPtr.Zero; //test relocation with this

            // try to allocate memory at arbitrary position
            if (memory == Pointer.Zero)
                memory = NativeMethods.AllocVirtualMemory(Pointer.Zero, (Pointer)ntHeaders.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);

            if (memory == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            if (Is64BitProcess && memory.SpanBoundary(regionSize, 32))
            {
                // Memory block may not span 4 GB (32 bit) boundaries.
                var blockedMemory = new System.Collections.Generic.List<Pointer>();
                while (memory.SpanBoundary(regionSize, 32))
                {
                    blockedMemory.Add(memory);
                    memory = NativeMethods.AllocVirtualMemory(Pointer.Zero, (Pointer)regionSize, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (memory == Pointer.Zero)
                        break;
                }
                foreach (var ptr in blockedMemory)
                    NativeMethods.FreeVirtualMemory(ptr, Pointer.Zero, AllocationType.RELEASE);
                if (memory == Pointer.Zero)
                    throw new ModuleException("Out of Memory");
            }

            return memory;
        }
    }
}
