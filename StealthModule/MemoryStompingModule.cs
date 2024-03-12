using StealthModule.ManualMap;
using System;

namespace StealthModule
{
    public partial class MemoryStompingModule : MemoryModuleBase
    {
        public ExportResolver Exports { get; }

        private Pointer targetAddress;

        /// <summary>
        /// Loads a unmanged (native) DLL in the memory at the desired address.
        /// </summary>
        /// <param name="data">Dll as a byte array</param>
        /// <param name="desiredAddress">The desired address to load the module. If it is not zero, the manual mapper assumes that the address is already allocated and zeroed. (Skip the allocation step) If it is zero, this parameter is ignored.</param>
        public MemoryStompingModule(byte[] data, Pointer targetAddress)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            this.targetAddress = targetAddress;

            memoryOp = new LocalMemoryStompingOperator();
            functionCall = new LocalFunctionCall();
            ManualMap(data);
            Exports = new ExportResolver(BaseAddress);
        }

        protected override Pointer AllocateBaseMemory(Pointer desiredAddress, uint regionSize) => targetAddress; // no additional memory allocation
    }
}
