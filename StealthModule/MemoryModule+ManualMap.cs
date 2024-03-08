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
        private void ManualMap(byte[] data)
        {
            if (data.Length < Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)))
                throw new BadImageFormatException("DOS header too small");
            var dosHeader = Structs.ReadOffset<IMAGE_DOS_HEADER>(data, 0);
            if (dosHeader.e_magic != Magic.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Invalid DOS header magic");

            if (data.Length < dosHeader.e_lfanew + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS)))
                throw new BadImageFormatException("NT header too small");
            var originalNtHeaders = Structs.ReadOffset<IMAGE_NT_HEADERS>(data, dosHeader.e_lfanew);

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
                var section = Structs.ReadOffset<IMAGE_SECTION_HEADER>(data, ofSection);
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
            importedModuleHandles = BuildIDT(moduleBase, ref originalNtHeaders);

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

        private static uint GetMachineType() => Is64BitProcess ? Magic.IMAGE_FILE_MACHINE_AMD64 : Magic.IMAGE_FILE_MACHINE_I386;

        private static uint AlignValueUp(uint value, uint alignment) => (value + alignment - 1) & ~(alignment - 1);
    }
}
