using StealthModule.ManualMap;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModuleBase
    {
        private ImageDosHeader dosHeader;
        private ImageNtHeaders ntHeaders;

        protected virtual void ManualMap(byte[] data)
        {
            if (memoryOp == null)
                throw new InvalidOperationException("set memoryOp before calling ManualMap");
            if (functionCall == null)
                throw new InvalidOperationException("set functionCall before calling ManualMap");

            dosHeader = ReadDosHeader(data);
            ntHeaders = ReadNtHeaders(data, dosHeader);

            IsDll = (ntHeaders.FileHeader.Characteristics & NativeMagics.IMAGE_FILE_DLL) != 0;

            NativeMethods.GetSystemPageSize(out var pageSize);

            var alignedImageSize = AlignValueUp(ntHeaders.OptionalHeader.SizeOfImage, pageSize);
            CheckSectionAlignment(ref data, ref dosHeader, ref ntHeaders, pageSize, alignedImageSize);

            var desiredBaseAddress = Is64BitProcess ? ((Pointer)unchecked((long)ntHeaders.OptionalHeader.ImageBaseLong)) : ((Pointer)unchecked((int)(ntHeaders.OptionalHeader.ImageBaseLong >> 32)));
            BaseAddress = AllocateBaseMemory(desiredBaseAddress, alignedImageSize);

            // commit memory for headers
            var headers = memoryOp.Allocate(BaseAddress, (Pointer)ntHeaders.OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (headers == Pointer.Zero)
                throw new ModuleException("Out of Memory");

            // copy PE header to code
            Marshal.Copy(data, 0, headers, (int)ntHeaders.OptionalHeader.SizeOfHeaders);
            ntHeadersAddress = headers + dosHeader.e_lfanew;

            var locationDelta = BaseAddress - desiredBaseAddress;
            if (locationDelta != Pointer.Zero)
            {
                // update relocated position
                var imageBaseAddress = ntHeadersAddress + (NativeOffsets.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? NativeOffsets64.IMAGE_OPTIONAL_HEADER_ImageBase : NativeOffsets32.IMAGE_OPTIONAL_HEADER_ImageBase));
                imageBaseAddress.Write((IntPtr)BaseAddress);
            }

            // copy sections from DLL file block to new memory location
            CopySections(ref data);

            // adjust base address of imported data
            isRelocated = locationDelta == Pointer.Zero || PerformBaseRelocation(locationDelta);

            // load required dlls and adjust function table of imports
            importModuleBaseAddresses = ResolveImports();

            // mark memory pages depending on section headers and release
            // sections that are marked as "discardable"
            FinalizeSections(pageSize);

            // TLS callbacks are executed BEFORE the main loading
            ExecuteTLS();

            // exception support
            // Only x64 use table-based exception handler
            // https://stackoverflow.com/questions/28549775/seh-handlers-using-rtladdfunctiontable#comment45413114_28549775
            RegisterExceptionTable();

            // get entry point of loaded library
            if (ntHeaders.OptionalHeader.AddressOfEntryPoint != 0)
                InitializeEntryPoint(functionCall, ref ntHeaders);
        }

        protected virtual void InitializeEntryPoint(IFunctionCaller caller, ref ImageNtHeaders ntHeaders)
        {
            if (IsDll)
            {
                // notify library about attaching to process
                var dllEntryPtr = BaseAddress + ntHeaders.OptionalHeader.AddressOfEntryPoint;
                wasDllMainSuccessful = caller.CallDllEntry(dllEntryPtr, BaseAddress, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                if (!wasDllMainSuccessful)
                    throw new ModuleException("DllMain returned false");
            }
            else
            {
                var exeEntryPtr = BaseAddress + ntHeaders.OptionalHeader.AddressOfEntryPoint;
                exeEntryPoint = (ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer(exeEntryPtr, typeof(ExeEntryDelegate));
            }
        }

        private static ImageDosHeader ReadDosHeader(byte[] data)
        {
            if (data.Length < Marshal.SizeOf(typeof(ImageDosHeader)))
                throw new BadImageFormatException("DOS header too small");
            var dosHeader = Structs.ReadOffset<ImageDosHeader>(data, 0);
            if (dosHeader.e_magic != NativeMagics.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Invalid DOS header magic");
            if (data.Length < dosHeader.e_lfanew + Marshal.SizeOf(typeof(ImageNtHeaders)))
                throw new BadImageFormatException("No sections found");
            return dosHeader;
        }

        private static ImageNtHeaders ReadNtHeaders(byte[] data, ImageDosHeader dosHeader)
        {
            var ntHeadersData = Structs.ReadOffset<ImageNtHeaders>(data, dosHeader.e_lfanew);

            if (ntHeadersData.Signature != NativeMagics.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Invalid NT Headers signature");
            if (ntHeadersData.FileHeader.Machine != GetMachineType())
                throw new BadImageFormatException("Machine type doesn't fit (i386 vs. AMD64)");
            if ((ntHeadersData.OptionalHeader.SectionAlignment & 1) > 0)
                throw new BadImageFormatException("Wrong section alignment header value: " + ntHeadersData.OptionalHeader.SectionAlignment); //Only support multiple of 2
            return ntHeadersData;
        }

        private static void CheckSectionAlignment(ref byte[] data, ref ImageDosHeader dosHeader, ref ImageNtHeaders ntHeadersData, uint pageSize, uint alignedImageSize)
        {
            uint lastSectionEnd = 0;
            var sectionOffset = NativeMethods.IMAGE_FIRST_SECTION(dosHeader.e_lfanew, ntHeadersData.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i != ntHeadersData.FileHeader.NumberOfSections; i++, sectionOffset += NativeSizes.IMAGE_SECTION_HEADER)
            {
                var sectionHeader = Structs.ReadOffset<ImageSectionHeader>(data, sectionOffset);
                var endOfSection = sectionHeader.VirtualAddress + (sectionHeader.SizeOfRawData > 0 ? sectionHeader.SizeOfRawData : ntHeadersData.OptionalHeader.SectionAlignment);
                if (endOfSection > lastSectionEnd)
                    lastSectionEnd = endOfSection;
            }

            var alignedLastSection = AlignValueUp(lastSectionEnd, pageSize);
            if (alignedImageSize != alignedLastSection)
                throw new BadImageFormatException("Wrong section alignment: imageSize=" + (Pointer)alignedImageSize + ", lastSectionEnd=" + (Pointer)alignedLastSection);
        }

        private static uint GetMachineType() => Is64BitProcess ? NativeMagics.IMAGE_FILE_MACHINE_AMD64 : NativeMagics.IMAGE_FILE_MACHINE_I386;

        private static uint AlignValueUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);
    }
}
