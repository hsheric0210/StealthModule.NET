using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.VisualStudio.TestTools.UnitTesting.Logging;
using System;
using System.IO;

namespace StealthModule.MemoryModuleTest.MemoryModuleTests
{
    [TestClass]
    public class ManualMapTest
    {
        // Dll list from: https://www.researchgate.net/figure/List-of-the-top-ranked-30-DLL-names-by-calling-frequency_tbl2_255787076

        [TestMethod]
        public void Kernel32() => TestManualMap("kernel32.dll");

        [TestMethod]
        public void Advapi32() => TestManualMap("advapi32.dll");

        [TestMethod]
        public void Gdi32() => TestManualMap("gdi32.dll");

        [TestMethod]
        public void Comctl32() => TestManualMap("comctl32.dll");

        [TestMethod]
        public void Wsock32() => TestManualMap("wsock32.dll");

        [TestMethod]
        public void Ws2_32() => TestManualMap("ws2_32.dll");

        [TestMethod]
        public void NtDLL() => TestManualMap("ntdll.dll");

        [TestMethod]
        public void Version() => TestManualMap("version.dll");

        [TestMethod]
        public void Comdlg32() => TestManualMap("comdlg32.dll");

        [TestMethod]
        public void Winmm() => TestManualMap("winmm.dll");

        [TestMethod]
        public void Rpcrt4() => TestManualMap("rpcrt4.dll");

        [TestMethod]
        public void Psapi() => TestManualMap("psapi.dll");

        [TestMethod]
        public void Hal() => TestManualMap("hal.dll");

        [TestMethod]
        public void Mpr() => TestManualMap("mpr.dll");

        [TestMethod]
        public void Netapi32() => TestManualMap("netapi32.dll");

        [TestMethod]
        public void Imagehlp() => TestManualMap("imagehlp.dll");

        [Ignore]
        private static void TestManualMap(string dllName)
        {
            var dllBytes = File.ReadAllBytes(Path.Combine(Environment.SystemDirectory, dllName));

            var mapped = new LocalMemoryModule(dllBytes);
            Logger.LogMessage("The dll {0} successfully manual-mapped to address {1}", dllName, mapped.BaseAddress);

            mapped.Dispose();
        }

        // excluded DLLs

        [Ignore] // DllMain always return false
        public void User32() => TestManualMap("user32.dll");

        [Ignore] // DllMain always return false
        public void Rasapi32() => TestManualMap("rasapi32.dll");

        [Ignore] // testhost crash with STATUS_ACCESS_VIOLATION
        public void Wininet() => TestManualMap("wininet.dll");

        [Ignore] // testhost crash with STATUS_ACCESS_VIOLATION
        public void Shell32() => TestManualMap("shell32.dll");

        [Ignore] // testhost crash with STATUS_ACCESS_VIOLATION
        public void Oleaut32() => TestManualMap("oleaut32.dll");

        [Ignore] // testhost crash with STATUS_ACCESS_VIOLATION
        public void Ole32() => TestManualMap("ole32.dll");

        [Ignore] // testhost crash with STATUS_ACCESS_VIOLATION
        public void Shlwapi() => TestManualMap("shlwapi.dll");

        [Ignore] // testhost crash with STATUS_ACCESS_VIOLATION
        public void Urlmon() => TestManualMap("urlmon.dll");

        [Ignore] // testhost crash with STATUS_ACCESS_VIOLATION
        public void Msvcr100() => TestManualMap("msvcr100.dll");
    }
}
