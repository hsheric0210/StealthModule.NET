using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace StealthModule
{
    /// <summary>
    /// Codes in this class are copied from DInvoke project:
    /// https://github.com/TheWover/DInvoke
    /// </summary>
    public partial class ExportResolver
    {
        private readonly Pointer moduleBase;

        private readonly IDictionary<string, Pointer> nameMapping = new Dictionary<string, Pointer>();
        private readonly IDictionary<int, Pointer> ordinalMapping = new Dictionary<int, Pointer>();

        public Pointer this[string functionName] => GetExport(functionName);

        public Pointer this[int functionOrdinal] => GetExport(functionOrdinal);

        public ExportResolver(Pointer moduleBase) => this.moduleBase = moduleBase;

        public ExportResolver(string moduleName) : this(GetModuleHandle(moduleName, throwIfNotFound: true)) { }

        public void CacheAllExports()
        {
            WalkEDT(entry =>
            {
                nameMapping[entry.FunctionName] = entry.FunctionAddress;
                ordinalMapping[entry.FunctionOrdinal] = entry.FunctionAddress;
                return false; // Iterate through all export entries
            });
        }

        public Pointer GetExport(string functionName)
        {
            if (nameMapping.TryGetValue(functionName, out var pointer))
                return pointer;

            var address = Pointer.Zero;
            WalkEDT(entry =>
            {
                if (string.Equals(entry.FunctionName, functionName, StringComparison.OrdinalIgnoreCase))
                {
                    address = entry.FunctionAddress;
                    return true; // break
                }

                return false; // continue
            });

            return nameMapping[functionName] = address;
        }

        public Pointer GetExport(int functionOrdinal)
        {
            if (ordinalMapping.TryGetValue(functionOrdinal, out var pointer))
                return pointer;

            var address = Pointer.Zero;
            WalkEDT(entry =>
            {
                if (entry.FunctionOrdinal == functionOrdinal)
                {
                    address = entry.FunctionAddress;
                    return true; // break
                }

                return false; // continue
            });

            return ordinalMapping[functionOrdinal] = address;
        }

        // Utility overloads

        public Delegate GetExport(string functionName, Type delegateType)
            => Marshal.GetDelegateForFunctionPointer(GetExport(functionName), delegateType);

        public Delegate GetExport(int functionOrdinal, Type delegateType)
            => Marshal.GetDelegateForFunctionPointer(GetExport(functionOrdinal), delegateType);

        public TDelegate GetExport<TDelegate>(string functionName) where TDelegate : class
#if NET451_OR_GREATER
            => Marshal.GetDelegateForFunctionPointer<TDelegate>(GetExport(functionName));
#else
            => Marshal.GetDelegateForFunctionPointer(GetExport(functionName), typeof(TDelegate)) as TDelegate;
#endif

        public TDelegate GetExport<TDelegate>(int functionOrdinal) where TDelegate : class
#if NET451_OR_GREATER
            => Marshal.GetDelegateForFunctionPointer<TDelegate>(GetExport(functionOrdinal));
#else
            => Marshal.GetDelegateForFunctionPointer(GetExport(functionOrdinal), typeof(TDelegate)) as TDelegate;
#endif

        // Export table walk

        public delegate bool ExportCallback(ExportEntry entry);

        public readonly struct ExportEntry
        {
            public string FunctionName { get; }
            public int FunctionOrdinal { get; }
            public Pointer FunctionAddress { get; }

            internal ExportEntry(string functionName, int functionOrdinal, Pointer functionAddress)
            {
                FunctionName = functionName;
                FunctionOrdinal = functionOrdinal;
                FunctionAddress = functionAddress;
            }
        }

        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base
        /// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
        /// manual export parsing. This function uses the .NET System.Diagnostics.Process class.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="moduleName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <param name="throwIfNotFound">Throw the <c>DLLException</c> when the specified DLL is not found from loaded module list.</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        /// <exception cref="ModuleException">Thrown when <paramref name="throwIfNotFound"/> is <c>true</c> and the specified <paramref name="moduleName"/> is not found from loaded module list.</exception>
        public static Pointer GetModuleHandle(string moduleName, bool throwIfNotFound = false)
        {
            var nameLower = moduleName.ToLower();
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.FileName.ToLower().EndsWith(nameLower))
                    return module.BaseAddress;
            }

            if (throwIfNotFound)
                throw new ModuleException("Module not found: " + moduleName);

            return Pointer.Zero;
        }

        /// <summary>
        /// Walk through the Export directory, calling the callback function for each Export entry.
        /// </summary>
        /// <param name="moduleBase">The base address of the module in memory.</param>
        /// <param name="callback">Callback function for each Export entry. Return <c>true</c> from the callback to stop the iteration.</param>
        /// <exception cref="ModuleException"></exception>
        public void WalkEDT(ExportCallback callback)
        {
            try
            {
                var dosMagic = moduleBase.Read<ushort>();
                if (dosMagic != 0x5A4D) // prevent calling WalkEDT() after erasing the PE header
                    throw new BadImageFormatException("Not a valid PE DOS header magic; Possibly your PE header is erased: " + dosMagic.ToString("X4"));

                // Traverse the PE header in memory
                var ntHeaders = Marshal.ReadInt32(moduleBase + 0x3C);
                var optionalHeader = moduleBase + ntHeaders + 0x18;
                var optionalHeaderMagic = Marshal.ReadInt16(optionalHeader);

                var edtAddress = optionalHeader + (optionalHeaderMagic == 0x010b ? 0x60 : 0x70); // 0x010B = NT64

                // Read -> IMAGE_EXPORT_DIRECTORY
                var edtRVA = Marshal.ReadInt32(edtAddress);
                var ordinalBase = Marshal.ReadInt32(moduleBase + edtRVA + 0x10);
                var numberOfNames = Marshal.ReadInt32(moduleBase + edtRVA + 0x18);
                var functionsRVA = Marshal.ReadInt32(moduleBase + edtRVA + 0x1C);
                var namesRVA = Marshal.ReadInt32(moduleBase + edtRVA + 0x20);
                var ordinalsRVA = Marshal.ReadInt32(moduleBase + edtRVA + 0x24);

                // Loop the array of export name RVA's
                for (var i = 0; i < numberOfNames; i++)
                {
                    var FunctionName = Marshal.PtrToStringAnsi(moduleBase + Marshal.ReadInt32(moduleBase + namesRVA + i * 4));
                    var FunctionOrdinal = Marshal.ReadInt16(moduleBase + ordinalsRVA + i * 2) + ordinalBase;
                    var FunctionRVA = Marshal.ReadInt32(moduleBase + functionsRVA + 4 * (FunctionOrdinal - ordinalBase));

                    var entry = new ExportEntry(FunctionName, FunctionOrdinal, moduleBase + FunctionRVA);
                    if (callback(entry))
                        break; // if callback returns true, stop the iteration.
                }
            }
            catch (Exception ex)
            {
                // Catch parser failure
                throw new ModuleException("Failed to parse module exports.", ex);
            }
        }
    }
}