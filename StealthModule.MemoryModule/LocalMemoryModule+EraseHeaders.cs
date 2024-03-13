using System;
using System.Runtime.InteropServices;
using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule
{
    public partial class LocalMemoryModule
    {
        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <typeparam name="TDelegate">The type of the delegate.</typeparam>
        /// <param name="functionName">The name of the function to be searched.</param>
        /// <returns>A delegate instance of type TDelegate</returns>
        /// <summary>
        /// <para>Overwrite the PE headers in the memory with random bytes to prevent getting memory dumped.</para>
        /// <para>
        /// Be careful! After this job done, you can no longer use the functions that access the PE header.
        /// For example, you can't resolve exports by calling 'GetExport' after erasing the PE header. (It will create errors)
        /// </para>
        /// Also, this may have other unintentional side effects such as:
        /// <list type="bullet">
        /// <item>Unable to use SEH(__try, __except, __finally) because the Exception data directory from the header is erased</item>
        /// <item>Unable to TLS(Thread-local Storage) because the TLS data directory from the header is erased</item>
        /// <item>Unable to access DLL resources because the Resources data directory from the header is erased</item>
        /// </list>
        /// See https://0xrick.github.io/win-internals/pe5/ for more header information
        /// </summary>
        /// <param name="random"></param>
        public void EraseHeaders(Random random = null)
        {
            // https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDump/ErasePEHeaderFromMemory.cpp

            const int headerSize = 0x1000; // '.text' section starts from 0x1000; all before that can be considered as header data.
            random = random ?? new Random();

            NativeMethods.ProtectVirtualMemory(BaseAddress, (Pointer)headerSize, MemoryProtection.READWRITE, out var oldProtection);

            for (var i = 0; i < headerSize; i++)
                Marshal.WriteByte(BaseAddress, i, (byte)random.Next(0xff));

            NativeMethods.ProtectVirtualMemory(BaseAddress, (Pointer)headerSize, oldProtection); // Revert protection to attempt perfect crime
        }
    }
}
