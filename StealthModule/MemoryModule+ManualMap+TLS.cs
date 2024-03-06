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
    public partial class MemoryModule
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void ImageTlsDelegate(IntPtr dllHandle, DllReason reason, IntPtr reserved);

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
    }
}
