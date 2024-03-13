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

            var e_lfanew = (uint)Marshal.ReadInt32(baseAddress + 0x3c);
            NtHeadersSignature = (uint)Marshal.ReadInt32(baseAddress + e_lfanew);

            // Validate PE signature
            if (NtHeadersSignature != NativeMagics.IMAGE_NT_SIGNATURE)
                throw new InvalidOperationException("Invalid PE signature.");

            FileHeader = (ImageFileHeader)Marshal.PtrToStructure(baseAddress + e_lfanew + 0x4, typeof(ImageFileHeader));

            var optHeaderAddress = baseAddress + e_lfanew + 0x18;
            OptionalHeader = (ImageOptionalHeader)Marshal.PtrToStructure(optHeaderAddress, typeof(ImageOptionalHeader));

            var optHeaderMagic = (ushort)Marshal.ReadInt16(optHeaderAddress);
            Is64Bit = optHeaderMagic == (uint)NtOptionalHeaderMagic.Header64Magic;

            // Read sections
            var sections = new ImageSectionHeader[FileHeader.NumberOfSections];
            for (var i = 0; i < sections.Length; i++)
            {
                var sectionHeaderAddress = optHeaderAddress + FileHeader.SizeOfOptionalHeader + (uint)(i * 0x28);
                sections[i] = (ImageSectionHeader)Marshal.PtrToStructure(sectionHeaderAddress, typeof(ImageSectionHeader));
            }

            Sections = sections;
        }
    }
}
