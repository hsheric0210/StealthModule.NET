using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        private void ManualMap(byte[] data, Pointer stompTargetAddress)
        {
            if (data.Length < Marshal.SizeOf(typeof(ImageDosHeader)))
                throw new BadImageFormatException("DOS header too small");
            var dosHeader = Structs.ReadOffset<ImageDosHeader>(data, 0);
            if (dosHeader.e_magic != NativeMagics.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Invalid DOS header magic");
            if (data.Length < dosHeader.e_lfanew + Marshal.SizeOf(typeof(ImageNtHeaders)))
                throw new BadImageFormatException("No sections found");

            var ntHeadersData = Structs.ReadOffset<ImageNtHeaders>(data, dosHeader.e_lfanew);

            if (ntHeadersData.Signature != NativeMagics.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Invalid NT Headers signature");
            if (ntHeadersData.FileHeader.Machine != GetMachineType())
                throw new BadImageFormatException("Machine type doesn't fit (i386 vs. AMD64)");
            if ((ntHeadersData.OptionalHeader.SectionAlignment & 1) > 0)
                throw new BadImageFormatException("Wrong section alignment"); //Only support multiple of 2

            IsDll = (ntHeadersData.FileHeader.Characteristics & NativeMagics.IMAGE_FILE_DLL) != 0;

            NativeMethods.GetSystemPageSize(out var pageSize);
            uint lastSectionEnd = 0;
            var sectionOffset = NativeMethods.IMAGE_FIRST_SECTION(dosHeader.e_lfanew, ntHeadersData.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i != ntHeadersData.FileHeader.NumberOfSections; i++, sectionOffset += NativeSizes.IMAGE_SECTION_HEADER)
            {
                var sectionHeader = Structs.ReadOffset<ImageSectionHeader>(data, sectionOffset);
                var endOfSection = sectionHeader.VirtualAddress + (sectionHeader.SizeOfRawData > 0 ? sectionHeader.SizeOfRawData : ntHeadersData.OptionalHeader.SectionAlignment);
                if (endOfSection > lastSectionEnd)
                    lastSectionEnd = endOfSection;
            }

            var alignedImageSize = AlignValueUp(ntHeadersData.OptionalHeader.SizeOfImage, pageSize);
            var alignedLastSection = AlignValueUp(lastSectionEnd, pageSize);
            if (alignedImageSize != alignedLastSection)
                throw new BadImageFormatException("Wrong section alignment");

            var desiredImageBase = Is64BitProcess ? ((Pointer)unchecked((long)ntHeadersData.OptionalHeader.ImageBaseLong)) : ((Pointer)unchecked((int)(ntHeadersData.OptionalHeader.ImageBaseLong >> 32)));
            var stomping = stompTargetAddress != Pointer.Zero;
            BaseAddress = stomping ? stompTargetAddress : AllocateBaseMemory(ref ntHeadersData, alignedImageSize, desiredImageBase);

            // commit memory for headers
            var headers = ConditionalVirtualAlloc(BaseAddress, (Pointer)ntHeadersData.OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE, stomping);
            if (headers == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            // copy PE header to code
            Marshal.Copy(data, 0, headers, (int)ntHeadersData.OptionalHeader.SizeOfHeaders);
            ntHeadersAddress = headers + dosHeader.e_lfanew;

            var locationDelta = BaseAddress - desiredImageBase;
            if (locationDelta != Pointer.Zero)
            {
                // update relocated position
                var imageBaseAddress = ntHeadersAddress + (NativeOffsets.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? NativeOffsets64.IMAGE_OPTIONAL_HEADER_ImageBase : NativeOffsets32.IMAGE_OPTIONAL_HEADER_ImageBase));
                imageBaseAddress.Write((IntPtr)BaseAddress);
            }

            // copy sections from DLL file block to new memory location
            CopySections(ref ntHeadersData, BaseAddress, ntHeadersAddress, data, stomping);

            // adjust base address of imported data
            isRelocated = locationDelta == Pointer.Zero || PerformBaseRelocation(ref ntHeadersData, BaseAddress, locationDelta);

            // load required dlls and adjust function table of imports
            importModuleBaseAddresses = BuildImportTable(ref ntHeadersData, BaseAddress);

            // mark memory pages depending on section headers and release
            // sections that are marked as "discardable"
            FinalizeSections(ref ntHeadersData, BaseAddress, ntHeadersAddress, pageSize);

            if (stomping) // When stomping, calling the module is mostly end up causing SEGFAULTs.
                return;

            // TLS callbacks are executed BEFORE the main loading
            ExecuteTLS(ref ntHeadersData, BaseAddress);

            // get entry point of loaded library
            if (ntHeadersData.OptionalHeader.AddressOfEntryPoint != 0)
            {
                if (IsDll)
                {
                    // notify library about attaching to process
                    var dllEntryPtr = BaseAddress + ntHeadersData.OptionalHeader.AddressOfEntryPoint;
                    dllEntryPoint = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(dllEntryPtr, typeof(DllEntryDelegate));
                    wasDllMainSuccessful = dllEntryPoint != null && dllEntryPoint(BaseAddress, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                    if (!wasDllMainSuccessful)
                        throw new ModuleException("Can't attach DLL to process");
                }
                else
                {
                    var exeEntryPtr = BaseAddress + ntHeadersData.OptionalHeader.AddressOfEntryPoint;
                    exeEntryPoint = (ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer(exeEntryPtr, typeof(ExeEntryDelegate));
                }
            }
        }

        private static uint GetMachineType() => Is64BitProcess ? NativeMagics.IMAGE_FILE_MACHINE_AMD64 : NativeMagics.IMAGE_FILE_MACHINE_I386;

        private static uint AlignValueUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);
    }
}
