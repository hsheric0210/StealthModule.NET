﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using StealthModule.MemoryModule.ManualMap;
using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule
{
    public abstract partial class MemoryModuleBase : IDisposable
    {
        public bool Disposed { get; private set; }

        public bool IsDll { get; private set; }

        public Pointer BaseAddress { get; private set; } = Pointer.Zero;

        private Pointer ntHeadersAddress = Pointer.Zero;
        private ICollection<Pointer> importModuleBaseAddresses;
        private bool wasDllMainSuccessful;
        private Pointer entryPointAddress;
        private bool isRelocated;

        protected IMemoryOperator memoryOp;
        protected IFunctionCaller functionCall;

        /// <summary>
        /// Call entry point of executable.
        /// </summary>
        /// <returns>Exitcode of executable</returns>
        public virtual int CallEntryPoint()
        {
            if (Disposed)
                throw new ObjectDisposedException("");
            if (IsDll || entryPointAddress == Pointer.Zero || !isRelocated)
                throw new ModuleException("Unable to call entry point. Is loaded module a dll?");

            return functionCall.CallExeEntry(entryPointAddress);
        }

        /// <summary>
        /// Check if the process runs in 64bit mode or in 32bit mode
        /// </summary>
        /// <returns>True if process is 64bit, false if it is 32bit</returns>
        public static bool Is64BitProcess => Pointer.Is64Bit;

        public void Close() => ((IDisposable)this).Dispose();

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (Disposed)
                return;

            if (disposing)
            {
                UninitializeDll();

                UnloadImports();
            }

            if (BaseAddress != Pointer.Zero)
            {
                memoryOp.Free(BaseAddress, IntPtr.Zero, AllocationType.RELEASE);
                BaseAddress = Pointer.Zero;
                ntHeadersAddress = Pointer.Zero;
            }

            Disposed = true;
        }

        protected virtual void UninitializeDll()
        {
            if (IsDll && wasDllMainSuccessful && entryPointAddress != Pointer.Zero)
            {
                functionCall.CallDllEntry(entryPointAddress, BaseAddress, DllReason.DLL_PROCESS_DETACH, Pointer.Zero);
                wasDllMainSuccessful = false;
            }
        }

        protected virtual void UnloadImports()
        {
            if (importModuleBaseAddresses != null)
            {
                foreach (var m in importModuleBaseAddresses)
                {
                    if (!m.IsInvalidHandle())
                        functionCall.FreeLibrary(m);
                }

                importModuleBaseAddresses = null;
            }
        }
    }
}
