using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        private static Pointer AllocateBaseMemory(ref ImageNtHeaders ntHeadersData, uint alignedImageSize, Pointer desiredImageBase)
        {

            // reserve memory for image of library
            var memory = NativeMethods.VirtualAlloc(desiredImageBase, ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
            //pCode = IntPtr.Zero; //test relocation with this

            // try to allocate memory at arbitrary position
            if (memory == Pointer.Zero)
                memory = NativeMethods.VirtualAlloc(Pointer.Zero, ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);

            if (memory == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            if (Is64BitProcess && memory.SpanBoundary(alignedImageSize, 32))
            {
                // Memory block may not span 4 GB (32 bit) boundaries.
                var blockedMemory = new System.Collections.Generic.List<Pointer>();
                while (memory.SpanBoundary(alignedImageSize, 32))
                {
                    blockedMemory.Add(memory);
                    memory = NativeMethods.VirtualAlloc(Pointer.Zero, alignedImageSize, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
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

        private static Pointer AllocateAndCopyNtHeaders(Pointer moduleBaseAddress, byte[] data, ImageDosHeader dosHeader, ImageNtHeaders ntHeadersData)
        {
            var headers = NativeMethods.VirtualAlloc(moduleBaseAddress, ntHeadersData.OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (headers == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            // copy PE header to code
            Marshal.Copy(data, 0, headers, (int)ntHeadersData.OptionalHeader.SizeOfHeaders);
            return headers + dosHeader.e_lfanew;
        }
    }
}
