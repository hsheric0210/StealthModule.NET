using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class MemoryModule : IDisposable
    {
        public bool Disposed { get; private set; }
        public bool IsDll { get; private set; }

        private Pointer moduleBaseAddress = Pointer.Zero;
        private Pointer ntHeadersAddress = Pointer.Zero;
        private Pointer[] importModuleBaseAddresses;
        private bool wasDllMainSuccessful;
        private DllEntryDelegate dllEntryPoint;
        private ExeEntryDelegate exeEntryPoint;
        private bool isRelocated;

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool DllEntryDelegate(IntPtr hinstDLL, DllReason fdwReason, IntPtr lpReserved);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int ExeEntryDelegate();

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
                throw new ObjectDisposedException("MemoryModule");
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
                dllEntryPoint?.Invoke(moduleBaseAddress, DllReason.DLL_PROCESS_DETACH, IntPtr.Zero);

                wasDllMainSuccessful = false;
            }

            if (importModuleBaseAddresses != null)
            {
                foreach (var m in importModuleBaseAddresses)
                {
                    if (!m.IsInvalidHandle())
                        NativeMethods.FreeLibrary(m);
                }

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
