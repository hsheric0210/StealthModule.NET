using System;
using System.IO;
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

        public bool Is64Bit { get; }

        public ImageDosHeader DosHeader { get; }

        // nt headers

        public ImageFileHeader FileHeader { get; }
        public ImageOptionalHeader OptionalHeader { get; }

        // section headers

        public ImageSectionHeader[] Sections { get; }

        private static class Constants
        {
            internal static int ImageNtHeaders_ImageFileHeader => 0x4;
            internal static int ImageNtHeaders_ImageOptionalHeader => 0x18;
            internal static int SectionHeaderSize => Marshal.SizeOf(typeof(ImageSectionHeader));
        }

        public PEHeader(Pointer baseAddress)
        {
            BaseAddress = baseAddress;

            DosHeader = baseAddress.Read<ImageDosHeader>();

            var ntHeadersAddress = baseAddress + DosHeader.e_lfanew;
            var ntHeadersSignature = ntHeadersAddress.Read<uint>();

            // Validate PE signature
            if (ntHeadersSignature != NativeMagics.IMAGE_NT_SIGNATURE)
                throw new InvalidOperationException("Invalid PE signature.");

            FileHeader = (baseAddress + DosHeader.e_lfanew + Constants.ImageNtHeaders_ImageFileHeader).Read<ImageFileHeader>();

            var optHeaderAddress = baseAddress + DosHeader.e_lfanew + Constants.ImageNtHeaders_ImageOptionalHeader;
            OptionalHeader = optHeaderAddress.Read<ImageOptionalHeader>();

            var optHeaderMagic = optHeaderAddress.Read<ushort>();
            Is64Bit = optHeaderMagic == (ushort)NtOptionalHeaderMagic.Header64Magic;

            // Read sections
            var sections = new ImageSectionHeader[FileHeader.NumberOfSections];
            for (var i = 0; i < sections.Length; i++)
            {
                var sectionHeaderAddress = optHeaderAddress + FileHeader.SizeOfOptionalHeader + (uint)(i * Constants.SectionHeaderSize);
                sections[i] = sectionHeaderAddress.Read<ImageSectionHeader>();
            }

            Sections = sections;
        }

        public static PEHeader GetFromBytes(byte[] peData)
        {
            var buffer = Marshal.AllocHGlobal(peData.Length);
            try
            {
                Marshal.Copy(peData, 0, buffer, peData.Length);
                return new PEHeader(buffer);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static PEHeader GetFromFile(string path) => GetFromBytes(File.ReadAllBytes(path));
    }
}
