using System;
using System.Runtime.InteropServices;
using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule
{
    internal class PEHeader
    {
        internal Pointer BaseAddress { get; }
        internal uint NtHeadersSignature { get; }
        internal bool Is64Bit { get; }
        internal ImageFileHeader FileHeader { get; }
        internal ImageOptionalHeader OptHeader { get; }
        internal ImageSectionHeader[] Sections { get; }

        public PEHeader(Pointer baseAddress)
        {
            BaseAddress = baseAddress;

            var e_lfanew = (uint)Marshal.ReadInt32((IntPtr)((ulong)baseAddress + 0x3c));
            NtHeadersSignature = (uint)Marshal.ReadInt32((IntPtr)((ulong)baseAddress + e_lfanew));

            // Validate PE signature
            if (NtHeadersSignature != 0x4550)
                throw new InvalidOperationException("Invalid PE signature.");

            FileHeader = (ImageFileHeader)Marshal.PtrToStructure((IntPtr)((ulong)baseAddress + e_lfanew + 0x4), typeof(ImageFileHeader));

            var optHeaderAddress = (IntPtr)((ulong)baseAddress + e_lfanew + 0x18);
            OptHeader = (ImageOptionalHeader)Marshal.PtrToStructure(optHeaderAddress, typeof(ImageOptionalHeader));

            var optHeaderMagic = (ushort)Marshal.ReadInt16(optHeaderAddress);
            Is64Bit = optHeaderMagic == 0x020b;

            // Read sections
            var sections = new ImageSectionHeader[FileHeader.NumberOfSections];
            for (var i = 0; i < sections.Length; i++)
            {
                var sectionHeaderAddress = (IntPtr)((ulong)optHeaderAddress + FileHeader.SizeOfOptionalHeader + (uint)(i * 0x28));
                sections[i] = (ImageSectionHeader)Marshal.PtrToStructure(sectionHeaderAddress, typeof(ImageSectionHeader));
            }

            Sections = sections;
        }
    }
}
