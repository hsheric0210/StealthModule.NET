using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModuleBase
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void ImageTlsDelegate(IntPtr dllHandle, DllReason reason, IntPtr reserved);

        protected virtual void ExecuteTLS()
        {
            if (ntHeaders.OptionalHeader.TLSTable.VirtualAddress == 0)
                return;

            var tlsDir = (BaseAddress + ntHeaders.OptionalHeader.TLSTable.VirtualAddress).Read<ImageTlsDirectory>();
            Pointer callBackAddress = tlsDir.AddressOfCallBacks;
            if (callBackAddress != Pointer.Zero)
            {
                for (Pointer Callback; (Callback = callBackAddress.Read()) != Pointer.Zero; callBackAddress += Pointer.Size)
                    functionCall.CallDllEntry(Callback, BaseAddress, DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
            }
        }
    }
}
