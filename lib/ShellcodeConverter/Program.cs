using StealthModule;
using StealthModule.Native.PE;
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace ShellcodeConverter
{
    internal class Program
    {
        private static void PrintSyntax()
        {
            Console.WriteLine("ShellCodeConverter (Out-Shellcode.ps1 ported to C# and StealthModule.NET) [original Out-Shellcode.ps1 by Matt Graeber @mattifestation]");
            Console.WriteLine("Syntax: ShellcodeConverter <input PE file path> <input .map file> <output file path>");
        }

        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                PrintSyntax();
                return;
            }

            var inputPEFile = args[0];
            var inputMapFile = args[1];
            var outputFile = args[2];

            if (!File.Exists(inputPEFile))
            {
                Console.WriteLine("Input PE file does not exist.");
                return;
            }

            if (!File.Exists(inputMapFile))
            {
                Console.WriteLine("Input .map file does not exist.");
                return;
            }

            var peBytes = File.ReadAllBytes(inputPEFile);
            var peBuffer = Marshal.AllocHGlobal(peBytes.Length);
            try
            {
                Marshal.Copy(peBytes, 0, peBuffer, peBytes.Length);
                var header = new PEHeader(peBuffer);

                var found = false;
                ImageSectionHeader textSection = default;
                foreach (var section in header.Sections)
                {
                    var sectionName = Structs.LongTo8byteString(section.Name);
                    Console.WriteLine("Section: " + sectionName);
                    if (sectionName.StartsWith(".text", StringComparison.Ordinal))
                    {
                        found = true;
                        textSection = section;
                        break;
                    }
                }

                if (!found)
                {
                    Console.WriteLine("'.text' section not found.");
                    return;
                }

                var lineMatcher = new Regex(@".*([\dabcdef]{8})H.*\.text(?:\$\w+)?.*\W+CODE", RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));
                var mapLines = File.ReadAllLines(inputMapFile);
                var textSectionLengthText = mapLines
                    .Select(line => lineMatcher.Match(line))
                    .Where(match => match.Success)
                    .Select(match => match.Groups[1].Value)
                    .FirstOrDefault();

                Console.WriteLine("'.text' section length is " + textSectionLengthText);

                if (textSectionLengthText == null || !int.TryParse(textSectionLengthText, NumberStyles.HexNumber, NumberFormatInfo.CurrentInfo, out var shellCodeLength))
                {
                    Console.WriteLine("'.text' section length is unavailable. (" + textSectionLengthText + ")");
                    return;
                }

                var shellCode = new byte[shellCodeLength];
                var textSectionBegin = textSection.PointerToRawData;
                Buffer.BlockCopy(peBytes, (int)textSectionBegin, shellCode, 0, shellCodeLength);

                Console.WriteLine("Shellcode extracted: offset=" + textSectionBegin + " length=" + shellCodeLength);

                File.WriteAllBytes(outputFile, shellCode);
                Console.WriteLine("Done writing to " + outputFile);
            }
            finally
            {
                Marshal.FreeHGlobal(peBuffer);
            }
        }
    }
}
