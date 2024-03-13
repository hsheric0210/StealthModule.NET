using System;

namespace StealthModule.ManualMap
{
    public interface IFunctionCaller
    {
        bool CallDllEntry(IntPtr functionAddress, IntPtr moduleHandle, DllReason callReason, IntPtr reserved);

        NTSTATUS AddFunctionTable(IntPtr functionTableAddress, uint functionTableSize, IntPtr baseAddress);

        Pointer LoadLibrary(string dllName);

        bool FreeLibrary(Pointer dllHandle);

        Pointer GetProcAddress(Pointer dllHandle, string functionName);

        Pointer GetProcAddress(Pointer dllHandle, ushort functionOrdinal);
    }
}
