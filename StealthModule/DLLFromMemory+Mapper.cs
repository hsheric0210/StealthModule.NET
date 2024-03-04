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
    public partial class DLLFromMemory : IDisposable
    {
        void MemoryLoadLibrary(byte[] data)
        {
            if (data.Length < Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)))
                throw new ModuleException("Not a valid executable file");
            var DosHeader = BytesReadStructAt<IMAGE_DOS_HEADER>(data, 0);
            if (DosHeader.e_magic != Magic.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Not a valid executable file");

            if (data.Length < DosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS)))
                throw new ModuleException("Not a valid executable file");
            var OrgNTHeaders = BytesReadStructAt<IMAGE_NT_HEADERS>(data, DosHeader.e_lfanew);

            if (OrgNTHeaders.Signature != Magic.IMAGE_NT_SIGNATURE)
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
            for (var i = 0; i != OrgNTHeaders.FileHeader.NumberOfSections; i++, ofSection += Sz.IMAGE_SECTION_HEADER)
            {
                var Section = BytesReadStructAt<IMAGE_SECTION_HEADER>(data, ofSection);
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
            if (pCode == IntPtr.Zero)
                pCode = NativeMethods.VirtualAlloc(IntPtr.Zero, (UIntPtr)OrgNTHeaders.OptionalHeader.SizeOfImage, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);

            if (pCode == IntPtr.Zero)
                throw new ModuleException("Out of Memory");

            if (Is64BitProcess && pCode.SpanBoundary(alignedImageSize, 32))
            {
                // Memory block may not span 4 GB (32 bit) boundaries.
                var BlockedMemory = new System.Collections.Generic.List<IntPtr>();
                while (pCode.SpanBoundary(alignedImageSize, 32))
                {
                    BlockedMemory.Add(pCode);
                    pCode = NativeMethods.VirtualAlloc(IntPtr.Zero, (UIntPtr)alignedImageSize, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (pCode == IntPtr.Zero)
                        break;
                }
                foreach (var ptr in BlockedMemory)
                    NativeMethods.VirtualFree(ptr, IntPtr.Zero, AllocationType.RELEASE);
                if (pCode == IntPtr.Zero)
                    throw new ModuleException("Out of Memory");
            }

            // commit memory for headers
            var headers = NativeMethods.VirtualAlloc(pCode, (UIntPtr)OrgNTHeaders.OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (headers == IntPtr.Zero)
                throw new ModuleException("Out of Memory");

            // copy PE header to code
            Marshal.Copy(data, 0, headers, (int)OrgNTHeaders.OptionalHeader.SizeOfHeaders);
            pNTHeaders = headers.Add(DosHeader.e_lfanew);

            var locationDelta = pCode.Subtract(oldHeader_OptionalHeader_ImageBase);
            if (locationDelta != IntPtr.Zero)
            {
                // update relocated position
                Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS), "OptionalHeader");
                Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER), "ImageBaseLong");
                var pImageBase = pNTHeaders.Add(Of.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? Of64.IMAGE_OPTIONAL_HEADER_ImageBase : Of32.IMAGE_OPTIONAL_HEADER_ImageBase));
                pImageBase.Write(pCode);
            }

            // copy sections from DLL file block to new memory location
            CopySections(ref OrgNTHeaders, pCode, pNTHeaders, data);

            // adjust base address of imported data
            _isRelocated = locationDelta != IntPtr.Zero ? PerformBaseRelocation(ref OrgNTHeaders, pCode, locationDelta) : true;

            // load required dlls and adjust function table of imports
            ImportModules = BuildImportTable(ref OrgNTHeaders, pCode);

            // mark memory pages depending on section headers and release
            // sections that are marked as "discardable"
            FinalizeSections(ref OrgNTHeaders, pCode, pNTHeaders, systemInfo.dwPageSize);

            // TLS callbacks are executed BEFORE the main loading
            ExecuteTLS(ref OrgNTHeaders, pCode, pNTHeaders);

            // get entry point of loaded library
            IsDll = (OrgNTHeaders.FileHeader.Characteristics & Magic.IMAGE_FILE_DLL) != 0;
            if (OrgNTHeaders.OptionalHeader.AddressOfEntryPoint != 0)
            {
                if (IsDll)
                {
                    // notify library about attaching to process
                    var dllEntryPtr = pCode.Add(OrgNTHeaders.OptionalHeader.AddressOfEntryPoint);
                    _dllEntry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(dllEntryPtr, typeof(DllEntryDelegate));

                    _initialized = _dllEntry != null && _dllEntry(pCode, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                    if (!_initialized)
                        throw new ModuleException("Can't attach DLL to process");
                }
                else
                {
                    var exeEntryPtr = pCode.Add(OrgNTHeaders.OptionalHeader.AddressOfEntryPoint);
                    _exeEntry = (ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer(exeEntryPtr, typeof(ExeEntryDelegate));
                }
            }
        }


        static void CopySections(ref IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode, IntPtr pNTHeaders, byte[] data)
        {
            var pSection = NativeMethods.IMAGE_FIRST_SECTION(pNTHeaders, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
            for (var i = 0; i < OrgNTHeaders.FileHeader.NumberOfSections; i++, pSection = pSection.Add(Sz.IMAGE_SECTION_HEADER))
            {
                var Section = pSection.Read<IMAGE_SECTION_HEADER>();
                if (Section.SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define uninitialized data
                    var size = OrgNTHeaders.OptionalHeader.SectionAlignment;
                    if (size > 0)
                    {
                        var dest = NativeMethods.VirtualAlloc(pCode.Add(Section.VirtualAddress), (UIntPtr)size, AllocationType.COMMIT, MemoryProtection.READWRITE);
                        if (dest == IntPtr.Zero)
                            throw new ModuleException("Unable to allocate memory");

                        // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                        dest = pCode.Add(Section.VirtualAddress);

                        // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                        pSection.Add(Of.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));

                        //NativeMethods.MemSet(dest, 0, (UIntPtr)size);
                        for (var j = 0; j < size; j++)
                            Marshal.WriteByte(dest, j, 0); // inefficient but at least it doesn't use any native function
                    }

                    // section is empty
                    continue;
                }
                else
                {
                    // commit memory block and copy data from dll
                    var dest = NativeMethods.VirtualAlloc(pCode.Add(Section.VirtualAddress), (UIntPtr)Section.SizeOfRawData, AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (dest == IntPtr.Zero)
                        throw new ModuleException("Out of memory");

                    // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                    dest = pCode.Add(Section.VirtualAddress);
                    Marshal.Copy(data, checked((int)Section.PointerToRawData), dest, checked((int)Section.SizeOfRawData));

                    // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                    pSection.Add(Of.IMAGE_SECTION_HEADER_PhysicalAddress).Write(unchecked((uint)(ulong)(long)dest));
                }
            }
        }

        static bool PerformBaseRelocation(ref IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode, IntPtr delta)
        {
            if (OrgNTHeaders.OptionalHeader.BaseRelocationTable.Size == 0)
                return delta == IntPtr.Zero;

            for (var pRelocation = pCode.Add(OrgNTHeaders.OptionalHeader.BaseRelocationTable.VirtualAddress); ;)
            {
                var Relocation = pRelocation.Read<IMAGE_BASE_RELOCATION>();
                if (Relocation.VirtualAdress == 0)
                    break;

                var pDest = pCode.Add(Relocation.VirtualAdress);
                var pRelInfo = pRelocation.Add(Sz.IMAGE_BASE_RELOCATION);
                var RelCount = (Relocation.SizeOfBlock - Sz.IMAGE_BASE_RELOCATION) / 2;
                for (uint i = 0; i != RelCount; i++, pRelInfo = pRelInfo.Add(sizeof(ushort)))
                {
                    var relInfo = (ushort)Marshal.PtrToStructure(pRelInfo, typeof(ushort));
                    var type = (BasedRelocationType)(relInfo >> 12); // the upper 4 bits define the type of relocation
                    var offset = relInfo & 0xfff; // the lower 12 bits define the offset
                    var pPatchAddr = pDest.Add(offset);

                    switch (type)
                    {
                        case BasedRelocationType.IMAGE_REL_BASED_ABSOLUTE:
                            // skip relocation
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_HIGHLOW:
                            // change complete 32 bit address
                            var patchAddrHL = (int)Marshal.PtrToStructure(pPatchAddr, typeof(int));
                            patchAddrHL += (int)delta;
                            Marshal.StructureToPtr(patchAddrHL, pPatchAddr, false);
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_DIR64:
                            var patchAddr64 = (long)Marshal.PtrToStructure(pPatchAddr, typeof(long));
                            patchAddr64 += (long)delta;
                            Marshal.StructureToPtr(patchAddr64, pPatchAddr, false);
                            break;
                    }
                }

                // advance to next relocation block
                pRelocation = pRelocation.Add(Relocation.SizeOfBlock);
            }
            return true;
        }

        static IntPtr[] BuildImportTable(ref IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode)
        {
            var ImportModules = new System.Collections.Generic.List<IntPtr>();
            var NumEntries = OrgNTHeaders.OptionalHeader.ImportTable.Size / Sz.IMAGE_IMPORT_DESCRIPTOR;
            var pImportDesc = pCode.Add(OrgNTHeaders.OptionalHeader.ImportTable.VirtualAddress);
            for (uint i = 0; i != NumEntries; i++, pImportDesc = pImportDesc.Add(Sz.IMAGE_IMPORT_DESCRIPTOR))
            {
                var ImportDesc = pImportDesc.Read<IMAGE_IMPORT_DESCRIPTOR>();
                if (ImportDesc.Name == 0)
                    break;

                var handle = NativeMethods.LoadLibrary(pCode.Add(ImportDesc.Name));
                if (handle.IsInvalidHandle())
                {
                    foreach (var m in ImportModules)
                        NativeMethods.FreeLibrary(m);
                    ImportModules.Clear();
                    throw new ModuleException("Can't load libary " + Marshal.PtrToStringAnsi(pCode.Add(ImportDesc.Name)));
                }
                ImportModules.Add(handle);

                IntPtr pThunkRef, pFuncRef;
                if (ImportDesc.OriginalFirstThunk > 0)
                {
                    pThunkRef = pCode.Add(ImportDesc.OriginalFirstThunk);
                    pFuncRef = pCode.Add(ImportDesc.FirstThunk);
                }
                else
                {
                    // no hint table
                    pThunkRef = pCode.Add(ImportDesc.FirstThunk);
                    pFuncRef = pCode.Add(ImportDesc.FirstThunk);
                }
                for (var SzRef = IntPtr.Size; ; pThunkRef = pThunkRef.Add(SzRef), pFuncRef = pFuncRef.Add(SzRef))
                {
                    IntPtr ReadThunkRef = pThunkRef.Read<IntPtr>(), WriteFuncRef;
                    if (ReadThunkRef == IntPtr.Zero)
                        break;
                    if (NativeMethods.IMAGE_SNAP_BY_ORDINAL(ReadThunkRef))
                    {
                        WriteFuncRef = NativeMethods.GetProcAddress(handle, NativeMethods.IMAGE_ORDINAL(ReadThunkRef));
                    }
                    else
                    {
                        WriteFuncRef = NativeMethods.GetProcAddress(handle, pCode.Add(ReadThunkRef).Add(Of.IMAGE_IMPORT_BY_NAME_Name));
                    }
                    if (WriteFuncRef == IntPtr.Zero)
                        throw new ModuleException("Can't get address for imported function");
                    pFuncRef.Write(WriteFuncRef);
                }
            }
            return ImportModules.Count > 0 ? ImportModules.ToArray() : null;
        }

        static void FinalizeSections(ref IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode, IntPtr pNTHeaders, uint PageSize)
        {
            var imageOffset = Is64BitProcess ? (UIntPtr)(unchecked((ulong)pCode.ToInt64()) & 0xffffffff00000000) : UIntPtr.Zero;
            var pSection = NativeMethods.IMAGE_FIRST_SECTION(pNTHeaders, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
            var Section = pSection.Read<IMAGE_SECTION_HEADER>();
            var sectionData = new SectionFinalizeData();
            sectionData.Address = IntPtr.Zero.Add(Section.PhysicalAddress).BitwiseOr(imageOffset);
            sectionData.AlignedAddress = sectionData.Address.AlignDown((UIntPtr)PageSize);
            sectionData.Size = GetRealSectionSize(ref Section, ref OrgNTHeaders);
            sectionData.Characteristics = Section.Characteristics;
            sectionData.Last = false;
            pSection = pSection.Add(Sz.IMAGE_SECTION_HEADER);

            // loop through all sections and change access flags
            for (var i = 1; i < OrgNTHeaders.FileHeader.NumberOfSections; i++, pSection = pSection.Add(Sz.IMAGE_SECTION_HEADER))
            {
                Section = pSection.Read<IMAGE_SECTION_HEADER>();
                var sectionAddress = IntPtr.Zero.Add(Section.PhysicalAddress).BitwiseOr(imageOffset);
                var alignedAddress = sectionAddress.AlignDown((UIntPtr)PageSize);
                var sectionSize = GetRealSectionSize(ref Section, ref OrgNTHeaders);

                // Combine access flags of all sections that share a page
                // TODO(fancycode): We currently share flags of a trailing large section with the page of a first small section. This should be optimized.
                var a = sectionData.Address.Add(sectionData.Size);
                ulong b = unchecked((ulong)a.ToInt64()), c = unchecked((ulong)alignedAddress);

                if (sectionData.AlignedAddress == alignedAddress || unchecked((ulong)sectionData.Address.Add(sectionData.Size).ToInt64()) > unchecked((ulong)alignedAddress))
                {
                    // Section shares page with previous
                    if ((Section.Characteristics & Magic.IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.Characteristics & Magic.IMAGE_SCN_MEM_DISCARDABLE) == 0)
                    {
                        sectionData.Characteristics = (sectionData.Characteristics | Section.Characteristics) & ~Magic.IMAGE_SCN_MEM_DISCARDABLE;
                    }
                    else
                    {
                        sectionData.Characteristics |= Section.Characteristics;
                    }
                    sectionData.Size = sectionAddress.Add(sectionSize).Subtract(sectionData.Address);
                    continue;
                }

                FinalizeSection(sectionData, PageSize, OrgNTHeaders.OptionalHeader.SectionAlignment);

                sectionData.Address = sectionAddress;
                sectionData.AlignedAddress = alignedAddress;
                sectionData.Size = sectionSize;
                sectionData.Characteristics = Section.Characteristics;
            }
            sectionData.Last = true;
            FinalizeSection(sectionData, PageSize, OrgNTHeaders.OptionalHeader.SectionAlignment);
        }

        static void FinalizeSection(SectionFinalizeData SectionData, uint PageSize, uint SectionAlignment)
        {
            if (SectionData.Size == IntPtr.Zero)
                return;

            if ((SectionData.Characteristics & Magic.IMAGE_SCN_MEM_DISCARDABLE) > 0)
            {
                // section is not needed any more and can safely be freed
                if (SectionData.Address == SectionData.AlignedAddress &&
                    (SectionData.Last ||
                        SectionAlignment == PageSize ||
                        unchecked((ulong)SectionData.Size.ToInt64()) % PageSize == 0)
                    )
                {
                    // Only allowed to decommit whole pages
                    NativeMethods.VirtualFree(SectionData.Address, SectionData.Size, AllocationType.DECOMMIT);
                }
                return;
            }

            // determine protection flags based on characteristics
            var readable = (SectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
            var writeable = (SectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;
            var executable = (SectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
            var protect = (uint)ProtectionFlags[executable, readable, writeable];
            if ((SectionData.Characteristics & Magic.IMAGE_SCN_MEM_NOT_CACHED) > 0)
                protect |= Magic.PAGE_NOCACHE;

            // change memory access flags
            if (!NativeMethods.VirtualProtect(SectionData.Address, SectionData.Size, protect, out var oldProtect))
                throw new ModuleException("Error protecting memory page");
        }

        static void ExecuteTLS(ref IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode, IntPtr pNTHeaders)
        {
            if (OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress == 0)
                return;
            var tlsDir = pCode.Add(OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress).Read<IMAGE_TLS_DIRECTORY>();
            var pCallBack = tlsDir.AddressOfCallBacks;
            if (pCallBack != IntPtr.Zero)
            {
                for (IntPtr Callback; (Callback = pCallBack.Read<IntPtr>()) != IntPtr.Zero; pCallBack = pCallBack.Add(IntPtr.Size))
                {
                    var tls = (ImageTlsDelegate)Marshal.GetDelegateForFunctionPointer(Callback, typeof(ImageTlsDelegate));
                    tls(pCode, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                }
            }
        }

        static IntPtr GetRealSectionSize(ref IMAGE_SECTION_HEADER Section, ref IMAGE_NT_HEADERS NTHeaders)
        {
            var size = Section.SizeOfRawData;
            if (size == 0)
            {
                if ((Section.Characteristics & Magic.IMAGE_SCN_CNT_INITIALIZED_DATA) > 0)
                {
                    size = NTHeaders.OptionalHeader.SizeOfInitializedData;
                }
                else if ((Section.Characteristics & Magic.IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
                {
                    size = NTHeaders.OptionalHeader.SizeOfUninitializedData;
                }
            }
            return IntPtr.Size == 8 ? (IntPtr)unchecked((long)size) : (IntPtr)unchecked((int)size);
        }
    }
}
