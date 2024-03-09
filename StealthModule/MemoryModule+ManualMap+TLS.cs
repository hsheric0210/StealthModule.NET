using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void ImageTlsDelegate(IntPtr dllHandle, DllReason reason, IntPtr reserved);

        private static void ExecuteTLS(ref ImageNtHeaders ntHeaders, Pointer moduleBaseAddress)
        {
            if (ntHeaders.OptionalHeader.TLSTable.VirtualAddress == 0)
                return;

            Console.WriteLine("tls table @ " + ntHeaders.OptionalHeader.TLSTable.VirtualAddress);
            var tlsDir = (moduleBaseAddress + ntHeaders.OptionalHeader.TLSTable.VirtualAddress).Read<ImageTlsDirectory>();
            Pointer callBackAddress = tlsDir.AddressOfCallBacks;
            if (callBackAddress != Pointer.Zero)
            {
                for (Pointer Callback; (Callback = callBackAddress.Read()) != Pointer.Zero; callBackAddress += Pointer.Size)
                {
                    Console.WriteLine("TLS callback addr " + Callback);
                    var tls = (ImageTlsDelegate)Marshal.GetDelegateForFunctionPointer(Callback, typeof(ImageTlsDelegate));
                    tls(moduleBaseAddress, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                }
            }
        }
    }
}
