using StealthModule.ManualMap;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace StealthModule
{
    public partial class LocalMemoryModule : MemoryModuleBase, IDisposable
    {
        public ExportResolver Exports { get; }

        /// <summary>
        /// Loads a unmanged (native) DLL in the memory at the desired address.
        /// </summary>
        /// <param name="data">Dll as a byte array</param>
        /// <param name="desiredAddress">The desired address to load the module. If it is not zero, the manual mapper assumes that the address is already allocated and zeroed. (Skip the allocation step) If it is zero, this parameter is ignored.</param>
        public LocalMemoryModule(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            memoryOp = new LocalMemoryOperator();
            functionCall = new LocalFunctionCall();
            ManualMap(data);
            Exports = new ExportResolver(BaseAddress);
        }

        ~LocalMemoryModule()
        {
            Dispose(false);
        }
    }
}
