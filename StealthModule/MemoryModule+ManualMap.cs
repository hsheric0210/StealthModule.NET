using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        void ManualMap(byte[] data)
        {
            if (data.Length < Marshal.SizeOf(typeof(ImageDosHeader)))
                throw new ModuleException("Not a valid executable file");
            var dosHeader = Structs.ReadOffset<ImageDosHeader>(data, 0);
            if (dosHeader.e_magic != NativeMagics.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Not a valid executable file");

            if (data.Length < dosHeader.e_lfanew + Marshal.SizeOf(typeof(ImageNtHeaders)))
                throw new ModuleException("Not a valid executable file");
            var ntHeadersData = Structs.ReadOffset<ImageNtHeaders>(data, dosHeader.e_lfanew);

            if (ntHeadersData.Signature != NativeMagics.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Not a valid PE file");
            if (ntHeadersData.FileHeader.Machine != GetMachineType())
                throw new BadImageFormatException("Machine type doesn't fit (i386 vs. AMD64)");
            if ((ntHeadersData.OptionalHeader.SectionAlignment & 1) > 0)
                throw new BadImageFormatException("Wrong section alignment"); //Only support multiple of 2
            if (ntHeadersData.OptionalHeader.AddressOfEntryPoint == 0)
                throw new ModuleException("Module has no entry point");

            NativeMethods.GetNativeSystemInfo(out var systemInfo);
            uint lastSectionEnd = 0;
            var sectionOffset = NativeMethods.IMAGE_FIRST_SECTION(dosHeader.e_lfanew, ntHeadersData.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i != ntHeadersData.FileHeader.NumberOfSections; i++, sectionOffset += NativeSizes.IMAGE_SECTION_HEADER)
            {
                var sectionHeader = Structs.ReadOffset<ImageSectionHeader>(data, sectionOffset);
                var endOfSection = sectionHeader.VirtualAddress + (sectionHeader.SizeOfRawData > 0 ? sectionHeader.SizeOfRawData : ntHeadersData.OptionalHeader.SectionAlignment);
                if (endOfSection > lastSectionEnd)
                    lastSectionEnd = endOfSection;
            }

            var alignedImageSize = AlignValueUp(ntHeadersData.OptionalHeader.SizeOfImage, systemInfo.dwPageSize);
            var alignedLastSection = AlignValueUp(lastSectionEnd, systemInfo.dwPageSize);
            if (alignedImageSize != alignedLastSection)
                throw new BadImageFormatException("Wrong section alignment");

            var desiredImageBase = Is64BitProcess ? ((Pointer)unchecked((long)ntHeadersData.OptionalHeader.ImageBaseLong)) : ((Pointer)unchecked((int)(ntHeadersData.OptionalHeader.ImageBaseLong >> 32)));

            // reserve memory for image of library
            moduleBaseAddress = NativeMethods.VirtualAlloc(desiredImageBase, ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
            //pCode = IntPtr.Zero; //test relocation with this

            // try to allocate memory at arbitrary position
            if (moduleBaseAddress == Pointer.Zero)
                moduleBaseAddress = NativeMethods.VirtualAlloc(Pointer.Zero, ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);

            if (moduleBaseAddress == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            if (Is64BitProcess && moduleBaseAddress.SpanBoundary(alignedImageSize, 32))
            {
                // Memory block may not span 4 GB (32 bit) boundaries.
                var blockedMemory = new System.Collections.Generic.List<Pointer>();
                while (moduleBaseAddress.SpanBoundary(alignedImageSize, 32))
                {
                    blockedMemory.Add(moduleBaseAddress);
                    moduleBaseAddress = NativeMethods.VirtualAlloc(Pointer.Zero, alignedImageSize, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (moduleBaseAddress == Pointer.Zero)
                        break;
                }
                foreach (var ptr in blockedMemory)
                    NativeMethods.VirtualFree(ptr, Pointer.Zero, AllocationType.RELEASE);
                if (moduleBaseAddress == Pointer.Zero)
                    throw new ModuleException("Out of Memory");
            }

            // commit memory for headers
            var headers = NativeMethods.VirtualAlloc(moduleBaseAddress, ntHeadersData.OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (headers == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            // copy PE header to code
            Marshal.Copy(data, 0, headers, (int)ntHeadersData.OptionalHeader.SizeOfHeaders);
            ntHeadersAddress = headers + dosHeader.e_lfanew;

            var locationDelta = moduleBaseAddress - desiredImageBase;
            if (locationDelta != Pointer.Zero)
            {
                // update relocated position
                var imageBaseAddress = ntHeadersAddress + (NativeOffsets.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? NativeOffsets64.IMAGE_OPTIONAL_HEADER_ImageBase : NativeOffsets32.IMAGE_OPTIONAL_HEADER_ImageBase));
                imageBaseAddress.Write((IntPtr)moduleBaseAddress);
            }

            // copy sections from DLL file block to new memory location
            CopySections(ref ntHeadersData, moduleBaseAddress, ntHeadersAddress, data);

            // adjust base address of imported data
            isRelocated = locationDelta == Pointer.Zero || PerformBaseRelocation(ref ntHeadersData, moduleBaseAddress, locationDelta);

            // load required dlls and adjust function table of imports
            importModuleBaseAddresses = BuildImportTable(ref ntHeadersData, moduleBaseAddress);

            // mark memory pages depending on section headers and release
            // sections that are marked as "discardable"
            FinalizeSections(ref ntHeadersData, moduleBaseAddress, ntHeadersAddress, systemInfo.dwPageSize);

            // TLS callbacks are executed BEFORE the main loading
            ExecuteTLS(ref ntHeadersData, moduleBaseAddress);

            // get entry point of loaded library
            IsDll = (ntHeadersData.FileHeader.Characteristics & NativeMagics.IMAGE_FILE_DLL) != 0;
            if (ntHeadersData.OptionalHeader.AddressOfEntryPoint != 0)
            {
                if (IsDll)
                {
                    // notify library about attaching to process
                    var dllEntryPtr = moduleBaseAddress + ntHeadersData.OptionalHeader.AddressOfEntryPoint;
                    dllEntryPoint = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(dllEntryPtr, typeof(DllEntryDelegate));

                    isInitialized = dllEntryPoint != null && dllEntryPoint(moduleBaseAddress, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                    if (!isInitialized)
                        throw new ModuleException("Can't attach DLL to process");
                }
                else
                {
                    var exeEntryPtr = moduleBaseAddress + ntHeadersData.OptionalHeader.AddressOfEntryPoint;
                    exeEntryPoint = (ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer(exeEntryPtr, typeof(ExeEntryDelegate));
                }
            }
        }

        static uint GetMachineType() => Is64BitProcess ? NativeMagics.IMAGE_FILE_MACHINE_AMD64 : NativeMagics.IMAGE_FILE_MACHINE_I386;

        static uint AlignValueUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);
    }
}
