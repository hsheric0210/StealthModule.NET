using StealthModule;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Linq;
using System.Threading;

namespace RunDll32
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                PrintSyntax();
                return;
            }

            var pieces = args[0].Split(',');
            if (pieces.Length != 2)
            {
                PrintSyntax();
                return;
            }

            var dllName = pieces[0];
            var entryPoint = pieces[1];
            if (dllName.Length <= 0 || entryPoint.Length <= 0)
            {
                PrintSyntax();
                return;
            }

            var cmdLine = string.Join(" ", args.Skip(1));
            RunDLL(dllName, entryPoint, cmdLine);
        }

        // https://blog.naver.com/ariesike/120133117676
        private delegate void DllEntryPoint(IntPtr hWindow, IntPtr hInstance, [MarshalAs(UnmanagedType.LPWStr)] string lpszCmdLine, int nCmdShow);

        [HandleProcessCorruptedStateExceptions] // Catch AccessViolationException
        private static void RunDLL(string dllName, string entryPointName, string cmdLine)
        {
            if (!File.Exists(dllName))
            {
                Console.WriteLine("[-] DLL file doesn't exist: " + dllName);
                return;
            }

            var dllBytes = File.ReadAllBytes(dllName);
            Console.WriteLine("[+] Read " + dllBytes.Length + " bytes from the disk. Begin manual mapping...");

            var module = new LocalMemoryModule(dllBytes);

            var entryPoint = entryPointName[0] == '#' ? module.Exports[int.Parse(entryPointName.Substring(1))] : module.Exports[entryPointName];
            if (entryPoint == Pointer.Zero)
            {
                Console.WriteLine("[-] The entry point function " + entryPointName + " not found.");
                return;
            }

            Console.WriteLine("[+] The entry point function " + entryPointName + " is at: " + entryPoint);

            try
            {
                var entry = Marshal.GetDelegateForFunctionPointer<DllEntryPoint>(entryPoint);

                Console.WriteLine($"[+] Command line is '{cmdLine}'");

                Thread.Sleep(10000);
                entry(IntPtr.Zero, module.BaseAddress, cmdLine, 1);// 1 = SW_NORMAL

                Console.WriteLine("[+] The entry point call was successful.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[+] The entry point call failed with an exception: " + ex);
            }
        }

        private static void PrintSyntax()
        {
            Console.WriteLine("RunDll32 implemented in C# with StealthModule.NET");
            Console.WriteLine("This program will manual-map the specified dll, and then call the specified entry point function.");
            Console.WriteLine("Some DLL would not work with this tool, especially for DLLs compiled with security features enabled (e.g. GS, SDL)");
            Console.WriteLine("Syntax: RunDll32.exe dll_name,EntryPoint [optional parameters]");
            Console.WriteLine("\tdll_name - The DLL file to run");
            Console.WriteLine("\tEntryPoint - The entry point function name or ordinal (to use ordinal the '#' prefix must be appended)");
            Console.WriteLine("\t[optional parameters] - Optional command line to pass through the DLL function.");
            Console.WriteLine("");
            Console.WriteLine("'Rundll32.exe abcd.dll,foobarbaz123' - Call the abcd.dll's 'foobarbaz123' exported function");
            Console.WriteLine("'Rundll32.exe efgh.dll,#1' - Call the efgh.dll's export function with ordinal 1");
        }
    }
}
