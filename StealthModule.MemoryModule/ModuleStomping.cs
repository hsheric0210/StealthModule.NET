using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using StealthModule.MemoryModule.Native;

namespace StealthModule.MemoryModule
{
    public class ModuleStomping
    {
        private FileMapping decoyModule;
        private MemoryStompingModule realModule;

        public Pointer BaseAddress { get; private set; }

        public ExportResolver Exports { get; private set; }

        public string DecoyModulePath { get; }

        public ModuleStomping(byte[] data, bool legitSigned = true)
        {
            DecoyModulePath = FindDecoyModule(data.Length, legitSigned);
            DoStomp(data);
        }

        public ModuleStomping(byte[] data, string decoyModulePath)
        {
            DecoyModulePath = decoyModulePath;
            DoStomp(data);
        }

        private void DoStomp(byte[] data)
        {
            if (string.IsNullOrEmpty(DecoyModulePath))
                throw new InvalidOperationException("DecoyModulePath");

            var decoySize = new FileInfo(DecoyModulePath).Length;
            if (decoySize < data.Length)
                throw new ArgumentException("Decoy module is too small to host the payload.");

            decoyModule = new FileMapping(DecoyModulePath);
            var decoyInfo = new PEHeader(decoyModule.BaseAddress);

            IntPtr decoyBase = decoyModule.BaseAddress;
            var decoyPeSize = (IntPtr)decoyInfo.OptionalHeader.SizeOfImage;
            var status = NativeMethods.NtProtectVirtualMemory(NativeMethods.GetCurrentProcess(), ref decoyBase, ref decoyPeSize, MemoryProtection.READWRITE, out _);
            if (!NativeMethods.NT_SUCCESS(status))
                throw new ModuleException("Failed to unprotect the decoy region: NtProtectVirtualMemory returned " + status);

            NativeMethods.RtlZeroMemory(decoyBase, (int)decoyPeSize);

            realModule = new MemoryStompingModule(data, decoyBase);
            BaseAddress = realModule.BaseAddress;
            Exports = realModule.Exports;
        }

        private static string FindDecoyModule(long minimumFileSize, bool legitSigned = true)
        {
            // Scan for DLLs
            var files = new List<string>(Directory.GetFiles(Environment.SystemDirectory, "*.dll"));

            // Exclude already loaded DLLs
            foreach (ProcessModule Module in Process.GetCurrentProcess().Modules)
            {
                var index = files.FindIndex(x => x.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase));
                if (index >= 0)
                    files.RemoveAt(index);
            }

            //Pick a random candidate that meets the requirements

            var random = new Random();

            //List of candidates that have been considered and rejected
            var exclusion = new List<int>();
            while (exclusion.Count != files.Count)
            {
                //Iterate through the list of files randomly
                var index = random.Next(0, files.Count);
                var candidate = files[index];

                //Check that the size of the module meets requirements
                if (!exclusion.Contains(index) && new FileInfo(candidate).Length >= minimumFileSize)
                {
                    //Check that the module meets signing requirements
                    if (legitSigned)
                    {
                        if (FileHasValidSignature(candidate))
                            return candidate;
                        else
                            exclusion.Add(index);
                    }
                    else
                    {
                        return candidate;
                    }
                }

                exclusion.Add(index);
            }

            return string.Empty;
        }

        /// <summary>
        /// Checks that a file is signed and has a valid signature.
        /// </summary>
        /// <param name="FilePath">Path of file to check.</param>
        /// <returns></returns>
        private static bool FileHasValidSignature(string FilePath)
        {
            X509Certificate2 FileCertificate;
            try
            {
                X509Certificate signer = X509Certificate.CreateFromSignedFile(FilePath);
                FileCertificate = new X509Certificate2(signer);
            }
            catch
            {
                return false;
            }

            X509Chain CertificateChain = new X509Chain();
            CertificateChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            CertificateChain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            CertificateChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            return CertificateChain.Build(FileCertificate);
        }

        public void Dispose()
        {
            realModule.Dispose();
            decoyModule.Dispose();
        }
    }
}
