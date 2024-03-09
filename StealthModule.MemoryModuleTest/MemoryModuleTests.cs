using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace StealthModule.MemoryModuleTest
{
    [TestClass]
    public class MemoryModuleTests
    {
        [TestMethod]
        public void LoadKernel32()
        {
            var kernel32Bytes = File.ReadAllBytes(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
            _ = new MemoryModule(kernel32Bytes);
        }
    }
}
