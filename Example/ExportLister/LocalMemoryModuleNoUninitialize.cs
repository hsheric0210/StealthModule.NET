using StealthModule;

namespace ExportLister
{
    internal class LocalMemoryModuleNoUninitialize : LocalMemoryModule
    {
        public LocalMemoryModuleNoUninitialize(byte[] data) : base(data)
        {
        }

        protected override void UninitializeDll() { }  // prevent DllMain with DLL_PROCESS_DETACH call because some DLLs might crash from this stage
    }
}
