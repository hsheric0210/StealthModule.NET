using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        static void ExecuteTLS(ref ImageNtHeaders OrgNTHeaders, Pointer pCode, IntPtr pNTHeaders)
        {
            if (OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress == 0)
                return;
            var tlsDir = (pCode + OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress).Read<ImageTlsDirectory>();
            Pointer pCallBack = tlsDir.AddressOfCallBacks;
            if (pCallBack != Pointer.Zero)
            {
                for (IntPtr Callback; (Callback = pCallBack.ReadPointer()) != IntPtr.Zero; pCallBack += IntPtr.Size)
                {
                    var tls = (ImageTlsDelegate)Marshal.GetDelegateForFunctionPointer(Callback, typeof(ImageTlsDelegate));
                    tls(pCode, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                }
            }
        }

    }
}
