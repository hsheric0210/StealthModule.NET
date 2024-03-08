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

namespace StealthModule
{
    internal static class NativeMagics
    {
        internal const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
        internal const uint IMAGE_NT_SIGNATURE = 0x00004550;
        internal const uint IMAGE_FILE_MACHINE_I386 = 0x014c;
        internal const uint IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        internal const uint IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
        internal const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
        internal const uint IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        internal const uint IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        internal const uint IMAGE_FILE_DLL = 0x2000;
    }

    internal static class NativeOffsets
    {
        internal const int IMAGE_NT_HEADERS_OptionalHeader = 24;
        internal const int IMAGE_SECTION_HEADER_PhysicalAddress = 8;
        internal const int IMAGE_IMPORT_BY_NAME_Name = 2;
    }

    internal static class NativeOffsets32
    {
        internal const int IMAGE_OPTIONAL_HEADER_ImageBase = 28;
        internal const int IMAGE_OPTIONAL_HEADER_ExportTable = 96;
    }

    internal static class NativeOffsets64
    {
        internal const int IMAGE_OPTIONAL_HEADER_ImageBase = 24;
        internal const int IMAGE_OPTIONAL_HEADER_ExportTable = 112;
    }

    internal static class NativeSizes
    {
        internal const int IMAGE_SECTION_HEADER = 40;
        internal const int IMAGE_BASE_RELOCATION = 8;
        internal const int IMAGE_IMPORT_DESCRIPTOR = 20;
    }
}
