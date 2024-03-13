namespace StealthModule.MemoryModule
{
    public partial class MemoryModuleBase
    {
        protected virtual void RegisterExceptionTable()
        {
            var exceptionTable = ntHeaders.OptionalHeader.ExceptionTable;
            if (exceptionTable.Size == 0 || !Pointer.Is64Bit) // Table-based exception handling is only used on x64
                return;

            // IMAGE_RUNTIME_FUNCTION_ENTRY : https://learn.microsoft.com/en-us/previous-versions/windows/embedded/ms879749(v=msdn.10)
            var entrySize = 28; // on x86 it is 20, but as RtlAddFucntionTable doesn't exist on x86 we don't need to consider it.
            var status = functionCall.AddFunctionTable(BaseAddress + exceptionTable.VirtualAddress, (uint)(exceptionTable.Size / entrySize), BaseAddress);
            if (!NativeMethods.NT_SUCCESS(status))
                throw new ModuleException("Failed to add exception table: NTSTATUS " + status);
        }
    }
}
