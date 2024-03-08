using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate void ImageTlsDelegate(IntPtr dllHandle, DllReason reason, IntPtr reserved);

        static void ExecuteTLS(ref ImageNtHeaders OrgNTHeaders, Pointer pCode, Pointer pNTHeaders)
        {
            if (OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress == 0)
                return;
            var tlsDir = (pCode + OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress).Read<ImageTlsDirectory>();
            Pointer pCallBack = tlsDir.AddressOfCallBacks;
            if (pCallBack != Pointer.Zero)
            {
                for (Pointer Callback; (Callback = pCallBack.Read()) != Pointer.Zero; pCallBack += Pointer.Size)
                {
                    var tls = (ImageTlsDelegate)Marshal.GetDelegateForFunctionPointer(Callback, typeof(ImageTlsDelegate));
                    tls(pCode, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                }
            }
        }
    }
}
