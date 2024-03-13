using System;
using System.Runtime.InteropServices;
using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule.ManualMap
{
    public class LocalFunctionCall : IFunctionCaller
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool DllEntry(Pointer hinstDLL, DllReason fdwReason, Pointer lpReserved);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int ExeEntry();

        public bool CallDllEntry(Pointer functionAddress, Pointer moduleHandle, DllReason callReason, Pointer reserved)
        {
            var call = (DllEntry)Marshal.GetDelegateForFunctionPointer(functionAddress, typeof(DllEntry));
            return call(moduleHandle, callReason, reserved);
        }

        public int CallExeEntry(Pointer functionAddress)
        {
            var call = (ExeEntry)Marshal.GetDelegateForFunctionPointer(functionAddress, typeof(ExeEntry));
            return call();
        }

        public NTSTATUS AddFunctionTable(Pointer functionTableAddress, uint functionTableSize, Pointer baseAddress)
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
