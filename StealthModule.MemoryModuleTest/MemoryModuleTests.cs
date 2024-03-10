using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace StealthModule.MemoryModuleTest
{
    [TestClass]
    public class MemoryModuleTests
    {
        [TestMethod]
        public void Kernel32()
        {
            var dllBytes = File.ReadAllBytes(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
            var mapped = new MemoryModule(dllBytes);
            _ = mapped.Exports["CloseHandle"];
        }

        [TestMethod]
        public void Shell32()
        {
            var dllBytes = File.ReadAllBytes(Path.Combine(Environment.SystemDirectory, "shell32.dll"));
            var mapped = new MemoryModule(dllBytes);
            _ = mapped.Exports["SHFree"];
        }
    }
}
