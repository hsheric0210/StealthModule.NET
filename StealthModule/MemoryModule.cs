using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule : IDisposable
    {
        public bool Disposed { get; private set; }
        public bool IsDll { get; private set; }

        Pointer moduleBaseAddress = Pointer.Zero;
        Pointer ntHeadersAddress = Pointer.Zero;
        Pointer[] importModuleBaseAddresses;
        bool wasDllMainSuccessful = false;
        DllEntryDelegate dllEntryPoint = null;
        ExeEntryDelegate exeEntryPoint = null;
        bool isRelocated = false;

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate bool DllEntryDelegate(IntPtr hinstDLL, DllReason fdwReason, IntPtr lpReserved);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate int ExeEntryDelegate();

        /// <summary>
        /// Loads a unmanged (native) DLL in the memory.
        /// </summary>
        /// <param name="data">Dll as a byte array</param>
        public MemoryModule(byte[] data)
        {
            Disposed = false;
            if (data == null)
                throw new ArgumentNullException("data");
            ManualMap(data);
        }

        ~MemoryModule()
        {
            Dispose();
        }

        /// <summary>
        /// Call entry point of executable.
        /// </summary>
        /// <returns>Exitcode of executable</returns>
        public int CallEntryPoint()
        {
            if (Disposed)
                throw new ObjectDisposedException("DLLFromMemory");
            if (IsDll || exeEntryPoint == null || !isRelocated)
                throw new ModuleException("Unable to call entry point. Is loaded module a dll?");
            return exeEntryPoint();
        }

        /// <summary>
        /// Check if the process runs in 64bit mode or in 32bit mode
        /// </summary>
        /// <returns>True if process is 64bit, false if it is 32bit</returns>
        public static bool Is64BitProcess => Pointer.Is64Bit;

        public void Close() => ((IDisposable)this).Dispose();

        void IDisposable.Dispose()
        {
            Dispose();
            GC.SuppressFinalize(this);
        }

        public void Dispose()
        {
            if (wasDllMainSuccessful)
            {
                if (dllEntryPoint != null)
                    dllEntryPoint.Invoke(moduleBaseAddress, DllReason.DLL_PROCESS_DETACH, IntPtr.Zero);
                wasDllMainSuccessful = false;
            }

            if (importModuleBaseAddresses != null)
            {
                foreach (var m in importModuleBaseAddresses)
                    if (!m.IsInvalidHandle())
                        NativeMethods.FreeLibrary(m);
                importModuleBaseAddresses = null;
            }

            if (moduleBaseAddress != Pointer.Zero)
            {
                NativeMethods.VirtualFree(moduleBaseAddress, IntPtr.Zero, AllocationType.RELEASE);
                moduleBaseAddress = Pointer.Zero;
                ntHeadersAddress = Pointer.Zero;
            }

            Disposed = true;
        }
    }
}
