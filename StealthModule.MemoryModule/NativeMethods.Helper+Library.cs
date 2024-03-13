using System;
using System.Runtime.InteropServices;

namespace StealthModule.MemoryModule
{
    internal static partial class NativeMethods
    {
        internal static Pointer LoadLibrary(string dllPath)
        {
            var moduleName = new UNICODE_STRING();
            RtlInitUnicodeString(ref moduleName, dllPath);
            var status = LdrLoadDll(IntPtr.Zero, 0, ref moduleName, out var moduleHandle);
            if (status != NTSTATUS.Success || moduleHandle == IntPtr.Zero || ((Pointer)moduleHandle).IsInvalidHandle())
                return Pointer.Zero;

            return moduleHandle;
        }

        internal static bool FreeLibrary(Pointer handle)
            => NT_SUCCESS(LdrUnloadDll(handle));

        internal static Pointer GetProcAddress(Pointer handle, string functionName)
        {
            var functionNameAnsiBuffer = Marshal.StringToHGlobalAnsi(functionName);
            var functionNameAnsi = new ANSI_STRING
            {
                Length = (ushort)functionName.Length,
                MaximumLength = (ushort)(functionName.Length * 2),
                Buffer = functionNameAnsiBuffer,
            };

            var functionNameBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(functionNameAnsi));
            try
            {
                Marshal.StructureToPtr(functionNameAnsi, functionNameBuffer, false);
                var status = LdrGetProcedureAddress(handle, functionNameBuffer, IntPtr.Zero, out var procAddress);
                if (!NT_SUCCESS(status))
                    return Pointer.Zero;

                return procAddress;
            }
            finally
            {
                Marshal.FreeHGlobal(functionNameBuffer);
                Marshal.FreeHGlobal(functionNameAnsiBuffer);
            }
        }

        internal static Pointer GetProcAddress(Pointer handle, int ordinal)
        {
            var status = LdrGetProcedureAddress(handle, IntPtr.Zero, (IntPtr)ordinal, out var procAddress);
            if (!NT_SUCCESS(status))
                return Pointer.Zero;

            return procAddress;
        }
    }
}
