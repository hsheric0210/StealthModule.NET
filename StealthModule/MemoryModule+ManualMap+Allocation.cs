using System;
using System.Runtime.InteropServices;
using static StealthModule.NativeMethods.Delegates;

namespace StealthModule
{
    public partial class MemoryModule
    {
        private static Pointer AllocateBaseMemory(ref ImageNtHeaders ntHeadersData, uint alignedImageSize, Pointer desiredImageBase)
        {

            // reserve memory for image of library
            var memory = NativeMethods.VirtualAlloc(desiredImageBase, (Pointer)ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
            //pCode = IntPtr.Zero; //test relocation with this

            // try to allocate memory at arbitrary position
            if (memory == Pointer.Zero)
                memory = NativeMethods.VirtualAlloc(Pointer.Zero, (Pointer)ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);

            if (memory == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            if (Is64BitProcess && memory.SpanBoundary(alignedImageSize, 32))
            {
                // Memory block may not span 4 GB (32 bit) boundaries.
                var blockedMemory = new System.Collections.Generic.List<Pointer>();
                while (memory.SpanBoundary(alignedImageSize, 32))
                {
                    blockedMemory.Add(memory);
                    memory = NativeMethods.VirtualAlloc(Pointer.Zero, (Pointer)alignedImageSize, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (memory == Pointer.Zero)
                        break;
                }
                foreach (var ptr in blockedMemory)
                    NativeMethods.VirtualFree(ptr, Pointer.Zero, AllocationType.RELEASE);
                if (memory == Pointer.Zero)
                    throw new ModuleException("Out of Memory");
            }

            return memory;
        }

        private static Pointer ConditionalVirtualAlloc(Pointer desiredAddress, Pointer size, AllocationType allocationType, MemoryProtection memoryProtection, bool noAllocation)
        {
            if (noAllocation)
                return desiredAddress;

            //return NativeMethods.VirtualAlloc(desiredAddress, size, allocationType, memoryProtection);
            IntPtr address = desiredAddress;
            IntPtr size2 = size;
            var status = NativeMethods.NtAllocateVirtualMemory(NativeMethods.GetCurrentProcess(), ref address, IntPtr.Zero, ref size2, allocationType, memoryProtection);
            if (!NativeMethods.NT_SUCCESS(status))
                throw new ModuleException("NtAllocateVirtualMemory returned " + status);

            return address;
        }
    }
}
