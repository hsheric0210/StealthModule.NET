using System.Runtime.InteropServices;

/* Unmerged change from project 'StealthModule.MemoryModule (net8.0-windows)'
Before:
using StealthModule.MemoryModule.Native;
After:
using StealthModule;
using StealthModule.MemoryModule.Native;
*/

namespace StealthModule.MemoryModule.Native
{
    [StructLayout(LayoutKind.Explicit)]
    public struct ApiSetNamespace
    {
        [FieldOffset(0x0C)]
        public int Count;

        [FieldOffset(0x10)]
        public int EntryOffset;
    }

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    public struct ApiSetNamespaceEntry
    {
        [FieldOffset(0x04)]
        public int NameOffset;

        [FieldOffset(0x08)]
        public int NameLength;

        [FieldOffset(0x10)]
        public int ValueOffset;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct ApiSetValueEntry
    {
        [FieldOffset(0x0C)]
        public int ValueOffset;

        [FieldOffset(0x10)]
        public int ValueCount;
    }
}
