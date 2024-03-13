using System;
using System.Runtime.InteropServices;

/* Unmerged change from project 'StealthModule (net8.0-windows)'
Before:
using StealthModule.MemoryModule.Native.PE;
After:
using StealthModule;
using StealthModule;
using StealthModule.MemoryModule.Native.PE;
*/
using StealthModule.Native.PE;

namespace StealthModule
{
    public class PEHeader
    {
        public Pointer BaseAddress { get; }
        public uint NtHeadersSignature { get; }
        public bool Is64Bit { get; }
        public ImageFileHeader FileHeader { get; }
        public ImageOptionalHeader OptionalHeader { get; }
        public ImageSectionHeader[] Sections { get; }

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
            OptionalHeader = (ImageOptionalHeader)Marshal.PtrToStructure(optHeaderAddress, typeof(ImageOptionalHeader));

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
