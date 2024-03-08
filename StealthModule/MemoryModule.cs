using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public class MemoryModule : IDisposable
    {
        public bool Disposed { get; private set; }
        public bool IsDll { get; private set; }

        IntPtr pCode = IntPtr.Zero;
        IntPtr pNTHeaders = IntPtr.Zero;
        IntPtr[] ImportModules;
        bool _initialized = false;
        DllEntryDelegate _dllEntry = null;
        ExeEntryDelegate _exeEntry = null;
        bool _isRelocated = false;

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate bool DllEntryDelegate(IntPtr hinstDLL, DllReason fdwReason, IntPtr lpReserved);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate int ExeEntryDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate void ImageTlsDelegate(IntPtr dllHandle, DllReason reason, IntPtr reserved);

        /// <summary>
        /// Loads a unmanged (native) DLL in the memory.
        /// </summary>
        /// <param name="data">Dll as a byte array</param>
        public MemoryModule(byte[] data)
        {
            Disposed = false;
            if (data == null)
                throw new ArgumentNullException("data");
            MemoryLoadLibrary(data);
        }

        ~MemoryModule()
        {
            Dispose();
        }

        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <typeparam name="TDelegate">The type of the delegate.</typeparam>
        /// <param name="funcName">The name of the function to be searched.</param>
        /// <returns>A delegate instance of type TDelegate</returns>
        public TDelegate GetDelegateFromFuncName<TDelegate>(string funcName) where TDelegate : class
        {
            if (!typeof(Delegate).IsAssignableFrom(typeof(TDelegate)))
                throw new ArgumentException(typeof(TDelegate).Name + " is not a delegate");
            TDelegate res = Marshal.GetDelegateForFunctionPointer((IntPtr)GetPtrFromFuncName(funcName), typeof(TDelegate)) as TDelegate;
            if (res == null)
                throw new ModuleException("Unable to get managed delegate");
            return res;
        }

        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <param name="funcName">The Name of the function to be searched.</param>
        /// <param name="delegateType">The type of the delegate to be returned.</param>
        /// <returns>A delegate instance that can be cast to the appropriate delegate type.</returns>
        public Delegate GetDelegateFromFuncName(string funcName, Type delegateType)
        {
            if (delegateType == null)
                throw new ArgumentNullException("delegateType");
            if (!typeof(Delegate).IsAssignableFrom(delegateType))
                throw new ArgumentException(delegateType.Name + " is not a delegate");
            Delegate res = Marshal.GetDelegateForFunctionPointer(GetPtrFromFuncName(funcName), delegateType);
            if (res == null)
                throw new ModuleException("Unable to get managed delegate");
            return res;
        }

        public IntPtr GetPtrFromFuncName(string funcName)
        {
            if (Disposed)
                throw new ObjectDisposedException("DLLFromMemory");
            if (string.IsNullOrEmpty(funcName))
                throw new ArgumentException("funcName");
            if (!IsDll)
                throw new InvalidOperationException("Loaded Module is not a DLL");
            if (!_initialized)
                throw new InvalidOperationException("Dll is not initialized");

            IntPtr pDirectory = PtrAdd(pNTHeaders, NativeOffsets.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? NativeOffsets64.IMAGE_OPTIONAL_HEADER_ExportTable : NativeOffsets32.IMAGE_OPTIONAL_HEADER_ExportTable));
            ImageDataDirectory Directory = PtrRead<ImageDataDirectory>(pDirectory);
            if (Directory.Size == 0)
                throw new ModuleException("Dll has no export table");

            IntPtr pExports = PtrAdd(pCode, Directory.VirtualAddress);
            ImageExportDirectory Exports = PtrRead<ImageExportDirectory>(pExports);
            if (Exports.NumberOfFunctions == 0 || Exports.NumberOfNames == 0)
                throw new ModuleException("Dll exports no functions");

            IntPtr pNameRef = PtrAdd(pCode, Exports.AddressOfNames);
            IntPtr pOrdinal = PtrAdd(pCode, Exports.AddressOfNameOrdinals);
            for (int i = 0; i < Exports.NumberOfNames; i++, pNameRef = PtrAdd(pNameRef, sizeof(uint)), pOrdinal = PtrAdd(pOrdinal, sizeof(ushort)))
            {
                uint NameRef = PtrRead<uint>(pNameRef);
                ushort Ordinal = PtrRead<ushort>(pOrdinal);
                string curFuncName = Marshal.PtrToStringAnsi(PtrAdd(pCode, NameRef));
                if (curFuncName == funcName)
                {
                    if (Ordinal > Exports.NumberOfFunctions)
                        throw new ModuleException("Invalid function ordinal");
                    IntPtr pAddressOfFunction = PtrAdd(pCode, (Exports.AddressOfFunctions + (uint)(Ordinal * 4)));
                    return PtrAdd(pCode, PtrRead<uint>(pAddressOfFunction));
                }
            }

            throw new ModuleException("Dll exports no function named " + funcName);
        }

        /// <summary>
        /// Call entry point of executable.
        /// </summary>
        /// <returns>Exitcode of executable</returns>
        public int MemoryCallEntryPoint()
        {
            if (Disposed)
                throw new ObjectDisposedException("DLLFromMemory");
            if (IsDll || _exeEntry == null || !_isRelocated)
                throw new ModuleException("Unable to call entry point. Is loaded module a dll?");
            return _exeEntry();
        }

        void MemoryLoadLibrary(byte[] data)
        {
            if (data.Length < Marshal.SizeOf(typeof(ImageDosHeader)))
                throw new ModuleException("Not a valid executable file");
            ImageDosHeader DosHeader = BytesReadStructAt<ImageDosHeader>(data, 0);
            if (DosHeader.e_magic != NativeMagics.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Not a valid executable file");

            if (data.Length < DosHeader.e_lfanew + Marshal.SizeOf(typeof(ImageNtHeaders)))
                throw new ModuleException("Not a valid executable file");
            ImageNtHeaders OrgNTHeaders = BytesReadStructAt<ImageNtHeaders>(data, DosHeader.e_lfanew);

            if (OrgNTHeaders.Signature != NativeMagics.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Not a valid PE file");
            if (OrgNTHeaders.FileHeader.Machine != GetMachineType())
                throw new BadImageFormatException("Machine type doesn't fit (i386 vs. AMD64)");
            if ((OrgNTHeaders.OptionalHeader.SectionAlignment & 1) > 0)
                throw new BadImageFormatException("Wrong section alignment"); //Only support multiple of 2
            if (OrgNTHeaders.OptionalHeader.AddressOfEntryPoint == 0)
                throw new ModuleException("Module has no entry point");

            SystemInfo systemInfo;
            NativeMethods.GetNativeSystemInfo(out systemInfo);
            uint lastSectionEnd = 0;
            int ofSection = NativeMethods.IMAGE_FIRST_SECTION(DosHeader.e_lfanew, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
            for (int i = 0; i != OrgNTHeaders.FileHeader.NumberOfSections; i++, ofSection += NativeSizes.IMAGE_SECTION_HEADER)
            {
                ImageSectionHeader Section = BytesReadStructAt<ImageSectionHeader>(data, ofSection);
                uint endOfSection = Section.VirtualAddress + (Section.SizeOfRawData > 0 ? Section.SizeOfRawData : OrgNTHeaders.OptionalHeader.SectionAlignment);
                if (endOfSection > lastSectionEnd)
                    lastSectionEnd = endOfSection;
            }

            uint alignedImageSize = AlignValueUp(OrgNTHeaders.OptionalHeader.SizeOfImage, systemInfo.dwPageSize);
            uint alignedLastSection = AlignValueUp(lastSectionEnd, systemInfo.dwPageSize);
            if (alignedImageSize != alignedLastSection)
                throw new BadImageFormatException("Wrong section alignment");

            IntPtr oldHeader_OptionalHeader_ImageBase;
            if (Is64BitProcess)
                oldHeader_OptionalHeader_ImageBase = (IntPtr)unchecked((long)(OrgNTHeaders.OptionalHeader.ImageBaseLong));
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

            if (Is64BitProcess && PtrSpanBoundary(pCode, alignedImageSize, 32))
            {
                // Memory block may not span 4 GB (32 bit) boundaries.
                System.Collections.Generic.List<IntPtr> BlockedMemory = new System.Collections.Generic.List<IntPtr>();
                while (PtrSpanBoundary(pCode, alignedImageSize, 32))
                {
                    BlockedMemory.Add(pCode);
                    pCode = NativeMethods.VirtualAlloc(IntPtr.Zero, (UIntPtr)alignedImageSize, AllocationType.RESERVE | AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (pCode == IntPtr.Zero)
                        break;
                }
                foreach (IntPtr ptr in BlockedMemory)
                    NativeMethods.VirtualFree(ptr, IntPtr.Zero, AllocationType.RELEASE);
                if (pCode == IntPtr.Zero)
                    throw new ModuleException("Out of Memory");
            }

            // commit memory for headers
            IntPtr headers = NativeMethods.VirtualAlloc(pCode, (UIntPtr)OrgNTHeaders.OptionalHeader.SizeOfHeaders, AllocationType.COMMIT, MemoryProtection.READWRITE);
            if (headers == IntPtr.Zero)
                throw new ModuleException("Out of Memory");

            // copy PE header to code
            Marshal.Copy(data, 0, headers, (int)(OrgNTHeaders.OptionalHeader.SizeOfHeaders));
            pNTHeaders = PtrAdd(headers, DosHeader.e_lfanew);

            IntPtr locationDelta = PtrSub(pCode, oldHeader_OptionalHeader_ImageBase);
            if (locationDelta != IntPtr.Zero)
            {
                // update relocated position
                Marshal.OffsetOf(typeof(ImageNtHeaders), "OptionalHeader");
                Marshal.OffsetOf(typeof(ImageOptionalHeader), "ImageBaseLong");
                IntPtr pImageBase = PtrAdd(pNTHeaders, NativeOffsets.IMAGE_NT_HEADERS_OptionalHeader + (Is64BitProcess ? NativeOffsets64.IMAGE_OPTIONAL_HEADER_ImageBase : NativeOffsets32.IMAGE_OPTIONAL_HEADER_ImageBase));
                PtrWrite(pImageBase, pCode);
            }

            // copy sections from DLL file block to new memory location
            CopySections(ref OrgNTHeaders, pCode, pNTHeaders, data);

            // adjust base address of imported data
            _isRelocated = (locationDelta != IntPtr.Zero ? PerformBaseRelocation(ref OrgNTHeaders, pCode, locationDelta) : true);

            // load required dlls and adjust function table of imports
            ImportModules = BuildImportTable(ref OrgNTHeaders, pCode);

            // mark memory pages depending on section headers and release
            // sections that are marked as "discardable"
            FinalizeSections(ref OrgNTHeaders, pCode, pNTHeaders, systemInfo.dwPageSize);

            // TLS callbacks are executed BEFORE the main loading
            ExecuteTLS(ref OrgNTHeaders, pCode, pNTHeaders);

            // get entry point of loaded library
            IsDll = ((OrgNTHeaders.FileHeader.Characteristics & NativeMagics.IMAGE_FILE_DLL) != 0);
            if (OrgNTHeaders.OptionalHeader.AddressOfEntryPoint != 0)
            {
                if (IsDll)
                {
                    // notify library about attaching to process
                    IntPtr dllEntryPtr = PtrAdd(pCode, OrgNTHeaders.OptionalHeader.AddressOfEntryPoint);
                    _dllEntry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(dllEntryPtr, typeof(DllEntryDelegate));

                    _initialized = (_dllEntry != null && _dllEntry(pCode, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero));
                    if (!_initialized)
                        throw new ModuleException("Can't attach DLL to process");
                }
                else
                {
                    IntPtr exeEntryPtr = PtrAdd(pCode, OrgNTHeaders.OptionalHeader.AddressOfEntryPoint);
                    _exeEntry = (ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer(exeEntryPtr, typeof(ExeEntryDelegate));
                }
            }
        }

        static void CopySections(ref ImageNtHeaders OrgNTHeaders, IntPtr pCode, IntPtr pNTHeaders, byte[] data)
        {
            IntPtr pSection = NativeMethods.IMAGE_FIRST_SECTION(pNTHeaders, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
            for (int i = 0; i < OrgNTHeaders.FileHeader.NumberOfSections; i++, pSection = PtrAdd(pSection, NativeSizes.IMAGE_SECTION_HEADER))
            {
                ImageSectionHeader Section = PtrRead<ImageSectionHeader>(pSection);
                if (Section.SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define uninitialized data
                    uint size = OrgNTHeaders.OptionalHeader.SectionAlignment;
                    if (size > 0)
                    {
                        IntPtr dest = NativeMethods.VirtualAlloc(PtrAdd(pCode, Section.VirtualAddress), (UIntPtr)size, AllocationType.COMMIT, MemoryProtection.READWRITE);
                        if (dest == IntPtr.Zero)
                            throw new ModuleException("Unable to allocate memory");

                        // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                        dest = PtrAdd(pCode, Section.VirtualAddress);

                        // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                        PtrWrite(PtrAdd(pSection, NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress), unchecked((uint)(ulong)(long)dest));

                        NativeMethods.MemSet(dest, 0, (UIntPtr)size);
                    }

                    // section is empty
                    continue;
                }
                else
                {
                    // commit memory block and copy data from dll
                    IntPtr dest = NativeMethods.VirtualAlloc(PtrAdd(pCode, Section.VirtualAddress), (UIntPtr)Section.SizeOfRawData, AllocationType.COMMIT, MemoryProtection.READWRITE);
                    if (dest == IntPtr.Zero)
                        throw new ModuleException("Out of memory");

                    // Always use position from file to support alignments smaller than page size (allocation above will align to page size).
                    dest = PtrAdd(pCode, Section.VirtualAddress);
                    Marshal.Copy(data, checked((int)Section.PointerToRawData), dest, checked((int)Section.SizeOfRawData));

                    // NOTE: On 64bit systems we truncate to 32bit here but expand again later when "PhysicalAddress" is used.
                    PtrWrite(PtrAdd(pSection, NativeOffsets.IMAGE_SECTION_HEADER_PhysicalAddress), unchecked((uint)(ulong)(long)dest));
                }
            }
        }

        static bool PerformBaseRelocation(ref ImageNtHeaders OrgNTHeaders, IntPtr pCode, IntPtr delta)
        {
            if (OrgNTHeaders.OptionalHeader.BaseRelocationTable.Size == 0)
                return (delta == IntPtr.Zero);

            for (IntPtr pRelocation = PtrAdd(pCode, OrgNTHeaders.OptionalHeader.BaseRelocationTable.VirtualAddress); ;)
            {
                ImageBaseRelocation Relocation = PtrRead<ImageBaseRelocation>(pRelocation);
                if (Relocation.VirtualAdress == 0)
                    break;

                IntPtr pDest = PtrAdd(pCode, Relocation.VirtualAdress);
                IntPtr pRelInfo = PtrAdd(pRelocation, NativeSizes.IMAGE_BASE_RELOCATION);
                uint RelCount = ((Relocation.SizeOfBlock - NativeSizes.IMAGE_BASE_RELOCATION) / 2);
                for (uint i = 0; i != RelCount; i++, pRelInfo = PtrAdd(pRelInfo, sizeof(ushort)))
                {
                    ushort relInfo = (ushort)Marshal.PtrToStructure(pRelInfo, typeof(ushort));
                    BasedRelocationType type = (BasedRelocationType)(relInfo >> 12); // the upper 4 bits define the type of relocation
                    int offset = (relInfo & 0xfff); // the lower 12 bits define the offset
                    IntPtr pPatchAddr = PtrAdd(pDest, offset);

                    switch (type)
                    {
                        case BasedRelocationType.IMAGE_REL_BASED_ABSOLUTE:
                            // skip relocation
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_HIGHLOW:
                            // change complete 32 bit address
                            int patchAddrHL = (int)Marshal.PtrToStructure(pPatchAddr, typeof(int));
                            patchAddrHL += (int)delta;
                            Marshal.StructureToPtr(patchAddrHL, pPatchAddr, false);
                            break;
                        case BasedRelocationType.IMAGE_REL_BASED_DIR64:
                            long patchAddr64 = (long)Marshal.PtrToStructure(pPatchAddr, typeof(long));
                            patchAddr64 += (long)delta;
                            Marshal.StructureToPtr(patchAddr64, pPatchAddr, false);
                            break;
                    }
                }

                // advance to next relocation block
                pRelocation = PtrAdd(pRelocation, Relocation.SizeOfBlock);
            }
            return true;
        }

        static IntPtr[] BuildImportTable(ref ImageNtHeaders OrgNTHeaders, IntPtr pCode)
        {
            System.Collections.Generic.List<IntPtr> ImportModules = new System.Collections.Generic.List<IntPtr>();
            uint NumEntries = OrgNTHeaders.OptionalHeader.ImportTable.Size / NativeSizes.IMAGE_IMPORT_DESCRIPTOR;
            IntPtr pImportDesc = PtrAdd(pCode, OrgNTHeaders.OptionalHeader.ImportTable.VirtualAddress);
            for (uint i = 0; i != NumEntries; i++, pImportDesc = PtrAdd(pImportDesc, NativeSizes.IMAGE_IMPORT_DESCRIPTOR))
            {
                ImageImportDescriptor ImportDesc = PtrRead<ImageImportDescriptor>(pImportDesc);
                if (ImportDesc.Name == 0)
                    break;

                IntPtr handle = NativeMethods.LoadLibrary(PtrAdd(pCode, ImportDesc.Name));
                if (PtrIsInvalidHandle(handle))
                {
                    foreach (IntPtr m in ImportModules)
                        NativeMethods.FreeLibrary(m);
                    ImportModules.Clear();
                    throw new ModuleException("Can't load libary " + Marshal.PtrToStringAnsi(PtrAdd(pCode, ImportDesc.Name)));
                }
                ImportModules.Add(handle);

                IntPtr pThunkRef, pFuncRef;
                if (ImportDesc.OriginalFirstThunk > 0)
                {
                    pThunkRef = PtrAdd(pCode, ImportDesc.OriginalFirstThunk);
                    pFuncRef = PtrAdd(pCode, ImportDesc.FirstThunk);
                }
                else
                {
                    // no hint table
                    pThunkRef = PtrAdd(pCode, ImportDesc.FirstThunk);
                    pFuncRef = PtrAdd(pCode, ImportDesc.FirstThunk);
                }
                for (int SzRef = IntPtr.Size; ; pThunkRef = PtrAdd(pThunkRef, SzRef), pFuncRef = PtrAdd(pFuncRef, SzRef))
                {
                    IntPtr ReadThunkRef = PtrRead<IntPtr>(pThunkRef), WriteFuncRef;
                    if (ReadThunkRef == IntPtr.Zero)
                        break;
                    if (NativeMethods.IMAGE_SNAP_BY_ORDINAL(ReadThunkRef))
                    {
                        WriteFuncRef = NativeMethods.GetProcAddress(handle, NativeMethods.IMAGE_ORDINAL(ReadThunkRef));
                    }
                    else
                    {
                        WriteFuncRef = NativeMethods.GetProcAddress(handle, PtrAdd(PtrAdd(pCode, ReadThunkRef), NativeOffsets.IMAGE_IMPORT_BY_NAME_Name));
                    }
                    if (WriteFuncRef == IntPtr.Zero)
                        throw new ModuleException("Can't get adress for imported function");
                    PtrWrite(pFuncRef, WriteFuncRef);
                }
            }
            return (ImportModules.Count > 0 ? ImportModules.ToArray() : null);
        }

        static void FinalizeSections(ref ImageNtHeaders OrgNTHeaders, IntPtr pCode, IntPtr pNTHeaders, uint PageSize)
        {
            UIntPtr imageOffset = (Is64BitProcess ? (UIntPtr)(unchecked((ulong)pCode.ToInt64()) & 0xffffffff00000000) : UIntPtr.Zero);
            IntPtr pSection = NativeMethods.IMAGE_FIRST_SECTION(pNTHeaders, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
            ImageSectionHeader Section = PtrRead<ImageSectionHeader>(pSection);
            SectionFinalizeData sectionData = new SectionFinalizeData();
            sectionData.Address = PtrBitOr(PtrAdd((IntPtr)0, Section.PhysicalAddress), imageOffset);
            sectionData.AlignedAddress = PtrAlignDown(sectionData.Address, (UIntPtr)PageSize);
            sectionData.Size = GetRealSectionSize(ref Section, ref OrgNTHeaders);
            sectionData.Characteristics = Section.Characteristics;
            sectionData.Last = false;
            pSection = PtrAdd(pSection, NativeSizes.IMAGE_SECTION_HEADER);

            // loop through all sections and change access flags
            for (int i = 1; i < OrgNTHeaders.FileHeader.NumberOfSections; i++, pSection = PtrAdd(pSection, NativeSizes.IMAGE_SECTION_HEADER))
            {
                Section = PtrRead<ImageSectionHeader>(pSection);
                IntPtr sectionAddress = PtrBitOr(PtrAdd((IntPtr)0, Section.PhysicalAddress), imageOffset);
                IntPtr alignedAddress = PtrAlignDown(sectionAddress, (UIntPtr)PageSize);
                IntPtr sectionSize = GetRealSectionSize(ref Section, ref OrgNTHeaders);

                // Combine access flags of all sections that share a page
                // TODO(fancycode): We currently share flags of a trailing large section with the page of a first small section. This should be optimized.
                IntPtr a = PtrAdd(sectionData.Address, sectionData.Size);
                ulong b = unchecked((ulong)a.ToInt64()), c = unchecked((ulong)alignedAddress);

                if (sectionData.AlignedAddress == alignedAddress || unchecked((ulong)PtrAdd(sectionData.Address, sectionData.Size).ToInt64()) > unchecked((ulong)alignedAddress))
                {
                    // Section shares page with previous
                    if ((Section.Characteristics & NativeMagics.IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.Characteristics & NativeMagics.IMAGE_SCN_MEM_DISCARDABLE) == 0)
                    {
                        sectionData.Characteristics = (sectionData.Characteristics | Section.Characteristics) & ~NativeMagics.IMAGE_SCN_MEM_DISCARDABLE;
                    }
                    else
                    {
                        sectionData.Characteristics |= Section.Characteristics;
                    }
                    sectionData.Size = PtrSub(PtrAdd(sectionAddress, sectionSize), sectionData.Address);
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

            if ((SectionData.Characteristics & NativeMagics.IMAGE_SCN_MEM_DISCARDABLE) > 0)
            {
                // section is not needed any more and can safely be freed
                if (SectionData.Address == SectionData.AlignedAddress &&
                    (SectionData.Last ||
                        SectionAlignment == PageSize ||
                        (unchecked((ulong)SectionData.Size.ToInt64()) % PageSize) == 0)
                    )
                {
                    // Only allowed to decommit whole pages
                    NativeMethods.VirtualFree(SectionData.Address, SectionData.Size, AllocationType.DECOMMIT);
                }
                return;
            }

            // determine protection flags based on characteristics
            int readable = (SectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
            int writeable = (SectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;
            int executable = (SectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
            var protect = ProtectionFlags[executable, readable, writeable];
            if ((SectionData.Characteristics & NativeMagics.IMAGE_SCN_MEM_NOT_CACHED) > 0)
                protect |= MemoryProtection.NOCACHE;

            // change memory access flags
            MemoryProtection oldProtect;
            if (!NativeMethods.VirtualProtect(SectionData.Address, SectionData.Size, protect, out oldProtect))
                throw new ModuleException("Error protecting memory page");
        }

        static void ExecuteTLS(ref ImageNtHeaders OrgNTHeaders, IntPtr pCode, IntPtr pNTHeaders)
        {
            if (OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress == 0)
                return;
            ImageTlsDirectory tlsDir = PtrRead<ImageTlsDirectory>(PtrAdd(pCode, OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress));
            IntPtr pCallBack = tlsDir.AddressOfCallBacks;
            if (pCallBack != IntPtr.Zero)
            {
                for (IntPtr Callback; (Callback = PtrRead<IntPtr>(pCallBack)) != IntPtr.Zero; pCallBack = PtrAdd(pCallBack, IntPtr.Size))
                {
                    ImageTlsDelegate tls = (ImageTlsDelegate)Marshal.GetDelegateForFunctionPointer(Callback, typeof(ImageTlsDelegate));
                    tls(pCode, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                }
            }
        }

        /// <summary>
        /// Check if the process runs in 64bit mode or in 32bit mode
        /// </summary>
        /// <returns>True if process is 64bit, false if it is 32bit</returns>
        public static bool Is64BitProcess { get { return IntPtr.Size == 8; } }

        static uint GetMachineType() { return (IntPtr.Size == 8 ? NativeMagics.IMAGE_FILE_MACHINE_AMD64 : NativeMagics.IMAGE_FILE_MACHINE_I386); }

        static uint AlignValueUp(uint value, uint alignment) { return (value + alignment - 1) & ~(alignment - 1); }

        static IntPtr GetRealSectionSize(ref ImageSectionHeader Section, ref ImageNtHeaders NTHeaders)
        {
            uint size = Section.SizeOfRawData;
            if (size == 0)
            {
                if ((Section.Characteristics & NativeMagics.IMAGE_SCN_CNT_INITIALIZED_DATA) > 0)
                {
                    size = NTHeaders.OptionalHeader.SizeOfInitializedData;
                }
                else if ((Section.Characteristics & NativeMagics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
                {
                    size = NTHeaders.OptionalHeader.SizeOfUninitializedData;
                }
            }
            return (IntPtr.Size == 8 ? (IntPtr)unchecked((long)size) : (IntPtr)unchecked((int)size));
        }

        public void Close() { ((IDisposable)this).Dispose(); }

        void IDisposable.Dispose()
        {
            Dispose();
            GC.SuppressFinalize(this);
        }

        public void Dispose()
        {
            if (_initialized)
            {
                if (_dllEntry != null)
                    _dllEntry.Invoke(pCode, DllReason.DLL_PROCESS_DETACH, IntPtr.Zero);
                _initialized = false;
            }

            if (ImportModules != null)
            {
                foreach (IntPtr m in ImportModules)
                    if (!PtrIsInvalidHandle(m))
                        NativeMethods.FreeLibrary(m);
                ImportModules = null;
            }

            if (pCode != IntPtr.Zero)
            {
                NativeMethods.VirtualFree(pCode, IntPtr.Zero, AllocationType.RELEASE);
                pCode = IntPtr.Zero;
                pNTHeaders = IntPtr.Zero;
            }

            Disposed = true;
        }

        // Protection flags for memory pages (Executable, Readable, Writeable)
        static readonly MemoryProtection[,,] ProtectionFlags = new MemoryProtection[2, 2, 2]
        {
        {
            // not executable
            { MemoryProtection.NOACCESS, MemoryProtection.WRITECOPY },
            { MemoryProtection.READONLY, MemoryProtection.READWRITE }
        },
        {
            // executable
            { MemoryProtection.EXECUTE, MemoryProtection.EXECUTE_WRITECOPY },
            { MemoryProtection.EXECUTE_READ, MemoryProtection.EXECUTE_READWRITE }
        }
        };
        struct SectionFinalizeData
        {
            internal IntPtr Address;
            internal IntPtr AlignedAddress;
            internal IntPtr Size;
            internal uint Characteristics;
            internal bool Last;
        }

        static T PtrRead<T>(IntPtr ptr) { return (T)Marshal.PtrToStructure(ptr, typeof(T)); }
        static void PtrWrite<T>(IntPtr ptr, T val) { Marshal.StructureToPtr(val, ptr, false); }
        static IntPtr PtrAdd(IntPtr p, int v) { return (IntPtr)(p.ToInt64() + v); }
        static IntPtr PtrAdd(IntPtr p, uint v) { return (IntPtr.Size == 8 ? (IntPtr)(p.ToInt64() + unchecked((long)v)) : (IntPtr)(p.ToInt32() + unchecked((int)v))); }
        static IntPtr PtrAdd(IntPtr p, IntPtr v) { return (IntPtr.Size == 8 ? (IntPtr)(p.ToInt64() + v.ToInt64()) : (IntPtr)(p.ToInt32() + v.ToInt32())); }
        static IntPtr PtrAdd(IntPtr p, UIntPtr v) { return (IntPtr.Size == 8 ? (IntPtr)(p.ToInt64() + unchecked((long)v.ToUInt64())) : (IntPtr)(p.ToInt32() + unchecked((int)v.ToUInt32()))); }
        static IntPtr PtrSub(IntPtr p, IntPtr v) { return (IntPtr.Size == 8 ? (IntPtr)(p.ToInt64() - v.ToInt64()) : (IntPtr)(p.ToInt32() - v.ToInt32())); }
        static IntPtr PtrBitOr(IntPtr p, UIntPtr v) { return (IntPtr.Size == 8 ? (IntPtr)unchecked((long)(unchecked((ulong)p.ToInt64()) | v.ToUInt64())) : (IntPtr)unchecked((int)(unchecked((uint)p.ToInt32()) | v.ToUInt32()))); }
        static IntPtr PtrAlignDown(IntPtr p, UIntPtr align) { return (IntPtr)unchecked((long)(unchecked((ulong)p.ToInt64()) & ~(align.ToUInt64() - 1))); }
        static bool PtrIsInvalidHandle(IntPtr h) { return (h == IntPtr.Zero || h == (IntPtr.Size == 8 ? (IntPtr)(long)-1 : (IntPtr)(int)-1)); }
        static bool PtrSpanBoundary(IntPtr p, uint Size, int BoundaryBits) { return ((unchecked((ulong)p.ToInt64()) >> BoundaryBits) < ((unchecked((ulong)(p.ToInt64())) + Size) >> BoundaryBits)); }

        static T BytesReadStructAt<T>(byte[] buf, int offset)
        {
            int size = Marshal.SizeOf(typeof(T));
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.Copy(buf, offset, ptr, size);
            T res = (T)Marshal.PtrToStructure(ptr, typeof(T));
            Marshal.FreeHGlobal(ptr);
            return res;
        }
    }
}
