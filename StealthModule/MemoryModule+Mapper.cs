/*
 * DLLFromMemory.Net
 *
 * Load a native DLL from memory without the need to allow unsafe code
 *
 * Copyright (C) 2018 - 2019 by Bernhard Schelling
 *
 * Based on Memory Module.net 0.2
 * Copyright (C) 2012 - 2018 by Andreas Kanzler (andi_kanzler(at)gmx.de)
 * https://github.com/Scavanger/MemoryModule.net
 *
 * Based on Memory DLL loading code Version 0.0.4
 * Copyright (C) 2004 - 2015 by Joachim Bauch (mail(at)joachim-bauch.de)
 * https://github.com/fancycode/MemoryModule
 *
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.c
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004 - 2015
 * Joachim Bauch. All Rights Reserved.
 *
 * Portions created by Andreas Kanzler are Copyright (C) 2012 - 2018
 * Andreas Kanzler. All Rights Reserved.
 *
 * Portions created by Bernhard Schelling are Copyright (C) 2018 - 2019
 * Bernhard Schelling. All Rights Reserved.
 *
 */

using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule : IDisposable
    {
        void MemoryLoadLibrary(byte[] data)
        {
            if (data.Length < Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)))
                throw new BadImageFormatException("DOS header too small");
            var dosHeader = data.ReadStruct<IMAGE_DOS_HEADER>(0);
            if (dosHeader.e_magic != Magic.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Invalid DOS header magic");

            if (data.Length < dosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS)))
                throw new BadImageFormatException("NT header too small");
            var originalNtHeaders = data.ReadStruct<IMAGE_NT_HEADERS>(dosHeader.e_lfanew);

            if (originalNtHeaders.Signature != Magic.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Invalid NT header signature");
            if (originalNtHeaders.FileHeader.Machine != GetMachineType())
                throw new BadImageFormatException("Machine type doesn't fit (i386 vs. AMD64)");
            if ((originalNtHeaders.OptionalHeader.SectionAlignment & 1) > 0)
                throw new BadImageFormatException("Unsupported section alignment: " + originalNtHeaders.OptionalHeader.SectionAlignment); //Only support multiple of 2
            if (originalNtHeaders.OptionalHeader.AddressOfEntryPoint == 0)
                throw new ModuleException("Module has no entry point");

            NativeMethods.GetNativeSystemInfo(out var systemInfo);
            uint lastSectionEnd = 0;
            var ofSection = NativeMethods.IMAGE_FIRST_SECTION(dosHeader.e_lfanew, originalNtHeaders.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i != originalNtHeaders.FileHeader.NumberOfSections; i++, ofSection += Sz.IMAGE_SECTION_HEADER)
            {
                var section = data.ReadStruct<IMAGE_SECTION_HEADER>(ofSection);
                var endOfSection = section.VirtualAddress + (section.SizeOfRawData > 0 ? section.SizeOfRawData : originalNtHeaders.OptionalHeader.SectionAlignment);
                if (endOfSection > lastSectionEnd)
                    lastSectionEnd = endOfSection;
            }

            var alignedImageSize = AlignValueUp(originalNtHeaders.OptionalHeader.SizeOfImage, systemInfo.dwPageSize);
            var alignedLastSection = AlignValueUp(lastSectionEnd, systemInfo.dwPageSize);
            if (alignedImageSize != alignedLastSection)
                throw new BadImageFormatException("Wrong section alignment: image=" + alignedImageSize + ", section=" + alignedLastSection);

            var preferredBaseAddress = (Pointer)(originalNtHeaders.OptionalHeader.ImageBaseLong >> (Is64BitProcess ? 0 : 32));

            moduleBase = AllocateModuleMemory(ref originalNtHeaders, alignedImageSize, preferredBaseAddress);

            ntHeaders = AllocateAndCopyHeaders(moduleBase, ref originalNtHeaders, data) + dosHeader.e_lfanew;

            var addressDelta = moduleBase - preferredBaseAddress;
            if (addressDelta != Pointer.Zero)
            {
                // update relocated position
                // fixme: is those OffsetOf calls necessary?
                Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS), "OptionalHeader");
                Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER), "ImageBaseLong");
                var pImageBase = ntHeaders + Of.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? Of64.IMAGE_OPTIONAL_HEADER_ImageBase : Of32.IMAGE_OPTIONAL_HEADER_ImageBase);
                pImageBase.Write(moduleBase);
            }

            // copy sections from DLL file block to new memory location
            CopySections(moduleBase, ref originalNtHeaders, ntHeaders, data);

            // adjust base address of imported data
            isRelocated = addressDelta == Pointer.Zero || PerformBaseRelocation(moduleBase, ref originalNtHeaders, addressDelta);

            // load required dlls and adjust function table of imports
            importedModuleHandles = BuildImportTable(moduleBase, ref originalNtHeaders);

            // mark memory pages depending on section headers and release sections that are marked as "discardable"
            FinalizeSections(moduleBase, ref originalNtHeaders, ntHeaders, systemInfo.dwPageSize);

            // TLS callbacks are executed BEFORE the main loading
            ExecuteTLS(moduleBase, ref originalNtHeaders);

            // get entry point of loaded library
            IsDll = (originalNtHeaders.FileHeader.Characteristics & Magic.IMAGE_FILE_DLL) != 0;
            if (originalNtHeaders.OptionalHeader.AddressOfEntryPoint != 0)
            {
                if (IsDll)
                {
                    // notify library about attaching to process
                    var dllEntryPtr = moduleBase + originalNtHeaders.OptionalHeader.AddressOfEntryPoint;
                    dllEntry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(dllEntryPtr, typeof(DllEntryDelegate)); // DllMain

                    isInitialized = dllEntry != null && dllEntry(moduleBase, DllReason.DLL_PROCESS_ATTACH, Pointer.Zero);
                    if (!isInitialized)
                        throw new ModuleException("Can't attach DLL to process");
                }
                else
                {
                    var exeEntryPtr = moduleBase + originalNtHeaders.OptionalHeader.AddressOfEntryPoint;
                    exeEntry = (ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer(exeEntryPtr, typeof(ExeEntryDelegate)); // main
                }
            }
        }

        private static Pointer AllocateAndCopyHeaders(Pointer moduleBase, ref IMAGE_NT_HEADERS ntHeadersData, byte[] data)
        {
            // commit memory for headers
            var headers = NativeMethods.VirtualAlloc(moduleBase, ntHeadersData.OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (headers == Pointer.Zero)
                throw new OutOfMemoryException("Header memory");

            // copy PE header to code
            Marshal.Copy(data, 0, headers, (int)ntHeadersData.OptionalHeader.SizeOfHeaders);
            return headers;
        }

        private static Pointer AllocateModuleMemory(ref IMAGE_NT_HEADERS ntHeadersData, uint alignedImageSize, Pointer preferredBaseAddress)
        {
            // reserve memory for image of library
            var mem = NativeMethods.VirtualAlloc(preferredBaseAddress, ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
            //pCode = Pointer.Zero; //test relocation with this

            // try to allocate memory at arbitrary position
            if (mem == Pointer.Zero)
                mem = NativeMethods.VirtualAlloc(Pointer.Zero, ntHeadersData.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);

            if (mem == Pointer.Zero)
                throw new OutOfMemoryException("Module memory");

            if (Is64BitProcess && mem.SpanBoundary(alignedImageSize, 32))
            {
                // Memory block may not span 4 GB (32 bit) boundaries.
                var blockedMemory = new System.Collections.Generic.List<IntPtr>();
                while (mem.SpanBoundary(alignedImageSize, 32))
                {
                    blockedMemory.Add(mem);
                    mem = NativeMethods.VirtualAlloc(Pointer.Zero, alignedImageSize, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (mem == Pointer.Zero)
                        break;
                }
                foreach (var ptr in blockedMemory)
                    NativeMethods.VirtualFree(ptr, Pointer.Zero, AllocationType.RELEASE);
                if (mem == Pointer.Zero)
                    throw new OutOfMemoryException("Module memory block");
            }

            return mem;
        }

        private static void CopySections(Pointer moduleBase, ref IMAGE_NT_HEADERS ntHeadersData, Pointer ntHeadersAddress, byte[] data)
        {
            var sectionBase = NativeMethods.IMAGE_FIRST_SECTION(ntHeadersAddress, ntHeadersData.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i < ntHeadersData.FileHeader.NumberOfSections; i++, sectionBase += Sz.IMAGE_SECTION_HEADER)
            {
                var sectionHeader = sectionBase.Read<IMAGE_SECTION_HEADER>();
                if (sectionHeader.SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define uninitialized data
                    var align = ntHeadersData.OptionalHeader.SectionAlignment;
                    if (align > 0)
                    {
                        var dest = NativeMethods.VirtualAlloc(moduleBase + sectionHeader.VirtualAddress, align, AllocationType.COMMIT, MemoryProtection.READWRITE);
                        if (dest == Pointer.Zero)
                            throw new ModuleException("Unable to allocate memory");

                        // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                        dest = moduleBase + sectionHeader.VirtualAddress;

                        // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                        (sectionBase + Of.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));

                        //NativeMethods.MemSet(dest, 0, (UIntPtr)size);
                        for (var j = 0; j < align; j++)
                            Marshal.WriteByte(dest, j, 0); // inefficient but at least it doesn't use any native function
                    }
                }
                else
                {
                    // commit memory block and copy data from dll
                    var dest = NativeMethods.VirtualAlloc(moduleBase + sectionHeader.VirtualAddress, sectionHeader.SizeOfRawData, AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (dest == Pointer.Zero)
                        throw new ModuleException("Out of memory");

                    // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                    dest = moduleBase + sectionHeader.VirtualAddress;
                    Marshal.Copy(data, checked((int)sectionHeader.PointerToRawData), dest, checked((int)sectionHeader.SizeOfRawData));

                    // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                    (sectionBase + Of.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));
                }
            }
        }

        private static bool PerformBaseRelocation(Pointer moduleBase, ref IMAGE_NT_HEADERS ntHeaders, Pointer delta)
        {
            if (ntHeaders.OptionalHeader.BaseRelocationTable.Size == 0)
                return delta == Pointer.Zero;

            for (var relocationTableAddress = moduleBase + ntHeaders.OptionalHeader.BaseRelocationTable.VirtualAddress; ;)
            {
                var relocationTable = relocationTableAddress.Read<IMAGE_BASE_RELOCATION>();
                if (relocationTable.VirtualAdress == 0)
                    break;

                var relocationBaseAddress = moduleBase + relocationTable.VirtualAdress;
                var relocationInfoAddress = relocationTableAddress + Sz.IMAGE_BASE_RELOCATION;
                var relocationCount = (relocationTable.SizeOfBlock - Sz.IMAGE_BASE_RELOCATION) / 2;
                for (uint i = 0; i != relocationCount; i++, relocationInfoAddress += sizeof(ushort))
                {
                    var relocationInfos = (ushort)Marshal.PtrToStructure(relocationInfoAddress, typeof(ushort));
                    var relocationType = (BasedRelocationType)(relocationInfos >> 12); // the upper 4 bits define the type of relocation
                    var relocationOffset = relocationInfos & 0xfff; // the lower 12 bits define the offset
                    var patchAddress = relocationBaseAddress + relocationOffset;

                    switch (relocationType)
                    {
                        case BasedRelocationType.IMAGE_REL_BASED_ABSOLUTE:
                            // skip relocation
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_HIGHLOW:
                            // change complete 32 bit address
                            var patchAddressHighLow = (int)Marshal.PtrToStructure(patchAddress, typeof(int));
                            patchAddressHighLow += (int)delta;
                            Marshal.StructureToPtr(patchAddressHighLow, patchAddress, false);
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_DIR64:
                            var patchAddress64 = (long)Marshal.PtrToStructure(patchAddress, typeof(long));
                            patchAddress64 += (long)delta;
                            Marshal.StructureToPtr(patchAddress64, patchAddress, false);
                            break;
                    }
                }

                // advance to next relocation block
                relocationTableAddress += relocationTable.SizeOfBlock;
            }

            return true;
        }

        private static Pointer[] BuildImportTable(Pointer moduleBase, ref IMAGE_NT_HEADERS ntHeaders)
        {
            var importModules = new System.Collections.Generic.List<Pointer>();
            var entryCount = ntHeaders.OptionalHeader.ImportTable.Size / Sz.IMAGE_IMPORT_DESCRIPTOR;
            var importDescriptorTableAddress = moduleBase + ntHeaders.OptionalHeader.ImportTable.VirtualAddress;
            for (uint i = 0; i != entryCount; i++, importDescriptorTableAddress += Sz.IMAGE_IMPORT_DESCRIPTOR)
            {
                var importDescriptor = importDescriptorTableAddress.Read<IMAGE_IMPORT_DESCRIPTOR>();
                if (importDescriptor.Name == 0)
                    break;

                var importModule = NativeMethods.LoadLibrary(moduleBase + importDescriptor.Name);
                if (importModule.IsInvalidHandle())
                {
                    foreach (var m in importModules)
                        NativeMethods.FreeLibrary(m);
                    importModules.Clear();
                    throw new ModuleException("Can't load libary " + Marshal.PtrToStringAnsi(moduleBase + importDescriptor.Name));
                }

                importModules.Add(importModule);

                Pointer thunkAddress, functionAddress;
                if (importDescriptor.OriginalFirstThunk > 0)
                {
                    thunkAddress = moduleBase + importDescriptor.OriginalFirstThunk;
                    functionAddress = moduleBase + importDescriptor.FirstThunk;
                }
                else
                {
                    // no hint table
                    thunkAddress = functionAddress = moduleBase + importDescriptor.FirstThunk;
                }

                for (var pointerSize = IntPtr.Size; ; thunkAddress += pointerSize, functionAddress += pointerSize)
                {
                    Pointer ReadThunkRef = thunkAddress.ReadPointer(), WriteFuncRef;
                    if (ReadThunkRef == Pointer.Zero)
                        break;

                    if (NativeMethods.IMAGE_SNAP_BY_ORDINAL(ReadThunkRef))
                        WriteFuncRef = NativeMethods.GetProcAddress(importModule, NativeMethods.IMAGE_ORDINAL(ReadThunkRef));
                    else
                        WriteFuncRef = NativeMethods.GetProcAddress(importModule, moduleBase + ReadThunkRef + Of.IMAGE_IMPORT_BY_NAME_Name);

                    if (WriteFuncRef == Pointer.Zero)
                        throw new ModuleException("Can't get address for imported function");

                    functionAddress.Write(WriteFuncRef);
                }
            }

            return importModules.Count > 0 ? importModules.ToArray() : Array.Empty<Pointer>();
        }

        private static void FinalizeSections(Pointer moduleBase, ref IMAGE_NT_HEADERS ntHeadersData, Pointer ntHeadersAddress, uint pageSize)
        {
            var imageOffset = Is64BitProcess ? ((ulong)moduleBase & 0xffffffff00000000) : Pointer.Zero;
            var sectionHeaderAddress = NativeMethods.IMAGE_FIRST_SECTION(ntHeadersAddress, ntHeadersData.FileHeader.SizeOfOptionalHeader);
            var sectionHeader = sectionHeaderAddress.Read<IMAGE_SECTION_HEADER>();

            var sectionData = new SectionFinalizeData();
            sectionData.Address = sectionHeader.PhysicalAddress | imageOffset;
            sectionData.AlignedAddress = sectionData.Address.AlignDown((UIntPtr)pageSize);
            sectionData.Size = GetRealSectionSize(ref sectionHeader, ref ntHeadersData);
            sectionData.Characteristics = sectionHeader.Characteristics;
            sectionData.Last = false;

            sectionHeaderAddress += Sz.IMAGE_SECTION_HEADER;

            // loop through all sections and change access flags
            for (var i = 1; i < ntHeadersData.FileHeader.NumberOfSections; i++, sectionHeaderAddress += Sz.IMAGE_SECTION_HEADER)
            {
                sectionHeader = sectionHeaderAddress.Read<IMAGE_SECTION_HEADER>();
                var sectionAddress = sectionHeader.PhysicalAddress | imageOffset;
                var alignedAddress = sectionAddress.AlignDown((UIntPtr)pageSize);
                var sectionSize = GetRealSectionSize(ref sectionHeader, ref ntHeadersData);

                // Combine access flags of all sections that share a page
                // TODO(fancycode): We currently share flags of a trailing large section with the page of a first small section. This should be optimized.
                var a = sectionData.Address + sectionData.Size;
                ulong b = (ulong)a, c = unchecked((ulong)alignedAddress);

                if (sectionData.AlignedAddress == alignedAddress || (ulong)(sectionData.Address + sectionData.Size) > (ulong)alignedAddress)
                {
                    // Section shares page with previous

                    if ((sectionHeader.Characteristics & Magic.IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.Characteristics & Magic.IMAGE_SCN_MEM_DISCARDABLE) == 0)
                        sectionData.Characteristics = (sectionData.Characteristics | sectionHeader.Characteristics) & ~Magic.IMAGE_SCN_MEM_DISCARDABLE;
                    else
                        sectionData.Characteristics |= sectionHeader.Characteristics;

                    sectionData.Size = sectionAddress + sectionSize - sectionData.Address;
                    continue;
                }

                FinalizeSection(sectionData, pageSize, ntHeadersData.OptionalHeader.SectionAlignment);

                sectionData.Address = sectionAddress;
                sectionData.AlignedAddress = alignedAddress;
                sectionData.Size = sectionSize;
                sectionData.Characteristics = sectionHeader.Characteristics;
            }

            sectionData.Last = true;
            FinalizeSection(sectionData, pageSize, ntHeadersData.OptionalHeader.SectionAlignment);
        }

        private static void FinalizeSection(SectionFinalizeData sectionData, uint pageSize, uint sectionAlignment)
        {
            if (sectionData.Size == Pointer.Zero)
                return;

            if ((sectionData.Characteristics & Magic.IMAGE_SCN_MEM_DISCARDABLE) > 0)
            {
                // section is not needed any more and can safely be freed
                if (sectionData.Address == sectionData.AlignedAddress && (sectionData.Last || sectionAlignment == pageSize || (ulong)sectionData.Size % pageSize == 0))
                {
                    // Only allowed to decommit whole pages
                    NativeMethods.VirtualFree(sectionData.Address, sectionData.Size, AllocationType.DECOMMIT);
                }
                return;
            }

            // determine protection flags based on characteristics
            var readable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
            var writeable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;
            var executable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
            var protect = (uint)ProtectionFlags[executable, readable, writeable];
            if ((sectionData.Characteristics & Magic.IMAGE_SCN_MEM_NOT_CACHED) > 0)
                protect |= Magic.PAGE_NOCACHE;

            // change memory access flags
            if (!NativeMethods.VirtualProtect(sectionData.Address, sectionData.Size, protect, out var oldProtect))
                throw new ModuleException("Error protecting memory page");
        }

        private static void ExecuteTLS(Pointer moduleBase, ref IMAGE_NT_HEADERS ntHeaders)
        {
            if (ntHeaders.OptionalHeader.TLSTable.VirtualAddress == 0) // no tls directory
                return;

            var tlsDir = (moduleBase + ntHeaders.OptionalHeader.TLSTable.VirtualAddress).Read<IMAGE_TLS_DIRECTORY>();
            Pointer tlsCallbackAddress = tlsDir.AddressOfCallBacks;
            if (tlsCallbackAddress != Pointer.Zero)
            {
                for (Pointer tlsCallback; (tlsCallback = tlsCallbackAddress.ReadPointer()) != Pointer.Zero; tlsCallbackAddress += Pointer.Size)
                {
                    var tls = (ImageTlsDelegate)Marshal.GetDelegateForFunctionPointer(tlsCallback, typeof(ImageTlsDelegate));
                    tls(moduleBase, DllReason.DLL_PROCESS_ATTACH, Pointer.Zero);
                }
            }
        }

        static IntPtr GetRealSectionSize(ref IMAGE_SECTION_HEADER sectionHeader, ref IMAGE_NT_HEADERS ntHeaders)
        {
            var size = sectionHeader.SizeOfRawData;
            if (size == 0)
            {
                if ((sectionHeader.Characteristics & Magic.IMAGE_SCN_CNT_INITIALIZED_DATA) > 0)
                    size = ntHeaders.OptionalHeader.SizeOfInitializedData;
                else if ((sectionHeader.Characteristics & Magic.IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
                    size = ntHeaders.OptionalHeader.SizeOfUninitializedData;
            }
            return IntPtr.Size == 8 ? (IntPtr)unchecked((long)size) : (IntPtr)unchecked((int)size);
        }
    }
}
