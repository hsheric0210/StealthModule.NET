using System;
using System.Runtime.InteropServices;

namespace StealthModule.MemoryModule.ManualMap
{
    public class LocalFunctionCall : IFunctionCaller
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool DllEntry(IntPtr hinstDLL, DllReason fdwReason, IntPtr lpReserved);

        public bool CallDllEntry(IntPtr functionAddress, IntPtr moduleHandle, DllReason callReason, IntPtr reserved)
        {
            var call = (DllEntry)Marshal.GetDelegateForFunctionPointer(functionAddress, typeof(DllEntry));
            return call(moduleHandle, callReason, reserved);
        }

        public NTSTATUS AddFunctionTable(IntPtr functionTableAddress, uint functionTableSize, IntPtr baseAddress)
            => NativeMethods.RtlAddFunctionTable(functionTableAddress, functionTableSize, (ulong)baseAddress);

        public Pointer GetProcAddress(Pointer dllHandle, string functionName)
            => NativeMethods.GetProcAddress(dllHandle, functionName);

        public Pointer GetProcAddress(Pointer dllHandle, ushort functionOrdinal)
            => NativeMethods.GetProcAddress(dllHandle, functionOrdinal);

        public Pointer LoadLibrary(string dllName)
        {
            var handle = ExportResolver.GetModuleHandle(dllName);

            if (handle.IsInvalidHandle())
                handle = NativeMethods.LoadLibrary(dllName);

            return handle;
        }

        public bool FreeLibrary(Pointer dllHandle)
            => NativeMethods.FreeLibrary(dllHandle);
    }
}
