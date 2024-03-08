using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        void MemoryLoadLibrary(byte[] data)
        {
            if (data.Length < Marshal.SizeOf(typeof(ImageDosHeader)))
                throw new ModuleException("Not a valid executable file");
            var DosHeader = Structs.ReadOffset<ImageDosHeader>(data, 0);
            if (DosHeader.e_magic != NativeMagics.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Not a valid executable file");

            if (data.Length < DosHeader.e_lfanew + Marshal.SizeOf(typeof(ImageNtHeaders)))
                throw new ModuleException("Not a valid executable file");
            var OrgNTHeaders = Structs.ReadOffset<ImageNtHeaders>(data, DosHeader.e_lfanew);

            if (OrgNTHeaders.Signature != NativeMagics.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Not a valid PE file");
            if (OrgNTHeaders.FileHeader.Machine != GetMachineType())
                throw new BadImageFormatException("Machine type doesn't fit (i386 vs. AMD64)");
            if ((OrgNTHeaders.OptionalHeader.SectionAlignment & 1) > 0)
                throw new BadImageFormatException("Wrong section alignment"); //Only support multiple of 2
            if (OrgNTHeaders.OptionalHeader.AddressOfEntryPoint == 0)
                throw new ModuleException("Module has no entry point");

            NativeMethods.GetNativeSystemInfo(out var systemInfo);
            uint lastSectionEnd = 0;
            var ofSection = NativeMethods.IMAGE_FIRST_SECTION(DosHeader.e_lfanew, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i != OrgNTHeaders.FileHeader.NumberOfSections; i++, ofSection += NativeSizes.IMAGE_SECTION_HEADER)
            {
                var Section = Structs.ReadOffset<ImageSectionHeader>(data, ofSection);
                var endOfSection = Section.VirtualAddress + (Section.SizeOfRawData > 0 ? Section.SizeOfRawData : OrgNTHeaders.OptionalHeader.SectionAlignment);
                if (endOfSection > lastSectionEnd)
                    lastSectionEnd = endOfSection;
            }

            var alignedImageSize = AlignValueUp(OrgNTHeaders.OptionalHeader.SizeOfImage, systemInfo.dwPageSize);
            var alignedLastSection = AlignValueUp(lastSectionEnd, systemInfo.dwPageSize);
            if (alignedImageSize != alignedLastSection)
                throw new BadImageFormatException("Wrong section alignment");

            IntPtr oldHeader_OptionalHeader_ImageBase;
            if (Is64BitProcess)
                oldHeader_OptionalHeader_ImageBase = (IntPtr)unchecked((long)OrgNTHeaders.OptionalHeader.ImageBaseLong);
            else
                oldHeader_OptionalHeader_ImageBase = (IntPtr)unchecked((int)(OrgNTHeaders.OptionalHeader.ImageBaseLong >> 32));

            // reserve memory for image of library
            pCode = NativeMethods.VirtualAlloc(oldHeader_OptionalHeader_ImageBase, (UIntPtr)OrgNTHeaders.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
            //pCode = IntPtr.Zero; //test relocation with this

            // try to allocate memory at arbitrary position
            if (pCode == Pointer.Zero)
                pCode = NativeMethods.VirtualAlloc(IntPtr.Zero, (UIntPtr)OrgNTHeaders.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);

            if (pCode == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            if (Is64BitProcess && pCode.SpanBoundary(alignedImageSize, 32))
            {
                // Memory block may not span 4 GB (32 bit) boundaries.
                var BlockedMemory = new System.Collections.Generic.List<IntPtr>();
                while (pCode.SpanBoundary(alignedImageSize, 32))
                {
                    BlockedMemory.Add(pCode);
                    pCode = NativeMethods.VirtualAlloc(IntPtr.Zero, (UIntPtr)alignedImageSize, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (pCode == Pointer.Zero)
                        break;
                }
                foreach (var ptr in BlockedMemory)
                    NativeMethods.VirtualFree(ptr, IntPtr.Zero, AllocationType.RELEASE);
                if (pCode == Pointer.Zero)
                    throw new ModuleException("Out of Memory");
            }

            // commit memory for headers
            var headers = NativeMethods.VirtualAlloc(pCode, (UIntPtr)OrgNTHeaders.OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (headers == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            // copy PE header to code
            Marshal.Copy(data, 0, headers, (int)OrgNTHeaders.OptionalHeader.SizeOfHeaders);
            pNTHeaders = headers + DosHeader.e_lfanew;

            IntPtr locationDelta = pCode - oldHeader_OptionalHeader_ImageBase;
            if (locationDelta != IntPtr.Zero)
            {
                // update relocated position
                Marshal.OffsetOf(typeof(ImageNtHeaders), "OptionalHeader");
                Marshal.OffsetOf(typeof(ImageOptionalHeader), "ImageBaseLong");
                var pImageBase = pNTHeaders + (NativeOffsets.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? NativeOffsets64.IMAGE_OPTIONAL_HEADER_ImageBase : NativeOffsets32.IMAGE_OPTIONAL_HEADER_ImageBase));
                pImageBase.Write((IntPtr)pCode);
            }

            // copy sections from DLL file block to new memory location
            CopySections(ref OrgNTHeaders, pCode, pNTHeaders, data);

            // adjust base address of imported data
            _isRelocated = locationDelta == IntPtr.Zero || PerformBaseRelocation(ref OrgNTHeaders, pCode, locationDelta);

            // load required dlls and adjust function table of imports
            ImportModules = BuildImportTable(ref OrgNTHeaders, pCode);

            // mark memory pages depending on section headers and release
            // sections that are marked as "discardable"
            FinalizeSections(ref OrgNTHeaders, pCode, pNTHeaders, systemInfo.dwPageSize);

            // TLS callbacks are executed BEFORE the main loading
            ExecuteTLS(ref OrgNTHeaders, pCode, pNTHeaders);

            // get entry point of loaded library
            IsDll = (OrgNTHeaders.FileHeader.Characteristics & NativeMagics.IMAGE_FILE_DLL) != 0;
            if (OrgNTHeaders.OptionalHeader.AddressOfEntryPoint != 0)
            {
                if (IsDll)
                {
                    // notify library about attaching to process
                    IntPtr dllEntryPtr = pCode + OrgNTHeaders.OptionalHeader.AddressOfEntryPoint;
                    _dllEntry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(dllEntryPtr, typeof(DllEntryDelegate));

                    _initialized = _dllEntry != null && _dllEntry(pCode, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                    if (!_initialized)
                        throw new ModuleException("Can't attach DLL to process");
                }
                else
                {
                    IntPtr exeEntryPtr = pCode + OrgNTHeaders.OptionalHeader.AddressOfEntryPoint;
                    _exeEntry = (ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer(exeEntryPtr, typeof(ExeEntryDelegate));
                }
            }
        }

        static uint GetMachineType() => IntPtr.Size == 8 ? NativeMagics.IMAGE_FILE_MACHINE_AMD64 : NativeMagics.IMAGE_FILE_MACHINE_I386;

        static uint AlignValueUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);
    }
}
