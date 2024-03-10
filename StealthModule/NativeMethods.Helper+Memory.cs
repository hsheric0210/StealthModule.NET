using System;

namespace StealthModule
{
    internal static partial class NativeMethods
    {
        internal static Pointer AllocVirtualMemory(Pointer baseAddress, IntPtr size, AllocationType allocationType, MemoryProtection protect)
        {
            IntPtr baseAddressPtr = baseAddress;
            var status = NtAllocateVirtualMemory(GetCurrentProcess(), ref baseAddressPtr, IntPtr.Zero, ref size, allocationType, protect);
            if (!NT_SUCCESS(status))
                return Pointer.Zero;

            return baseAddressPtr;
        }

        internal static bool ProtectVirtualMemory(Pointer baseAddress, IntPtr size, MemoryProtection protect)
            => ProtectVirtualMemory(baseAddress, size, protect, out _);

        internal static bool ProtectVirtualMemory(Pointer baseAddress, IntPtr size, MemoryProtection protect, out MemoryProtection prevProtect)
        {
            IntPtr baseAddressPtr = baseAddress;
            return NT_SUCCESS(NtProtectVirtualMemory(GetCurrentProcess(), ref baseAddressPtr, ref size, protect, out prevProtect));
        }

        internal static bool FreeVirtualMemory(Pointer baseAddress, IntPtr size, AllocationType freeType)
            => NT_SUCCESS(NtFreeVirtualMemory(GetCurrentProcess(), baseAddress, ref size, freeType));
    }
}
