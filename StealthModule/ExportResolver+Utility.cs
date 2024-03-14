using System;

namespace StealthModule
{
    /// <summary>
    /// Codes in this class are copied from DInvoke project:
    /// https://github.com/TheWover/DInvoke
    /// </summary>
    public partial class ExportResolver
    {
        public static Pointer ResolveExport(Pointer moduleBase, string exportName)
            => new ExportResolver(moduleBase).GetExport(exportName);

        public static Pointer ResolveExport(string moduleName, string exportName)
            => new ExportResolver(moduleName).GetExport(exportName);

        public static Delegate ResolveExport(Pointer moduleBase, string exportName, Type delegateType)
            => new ExportResolver(moduleBase).GetExport(exportName, delegateType);

        public static Delegate ResolveExport(string moduleName, string exportName, Type delegateType)
            => new ExportResolver(moduleName).GetExport(exportName, delegateType);
        public static TDelegate ResolveExport<TDelegate>(Pointer moduleBase, string exportName) where TDelegate : class
            => new ExportResolver(moduleBase).GetExport<TDelegate>(exportName);

        public static TDelegate ResolveExport<TDelegate>(string moduleName, string exportName) where TDelegate : class
            => new ExportResolver(moduleName).GetExport<TDelegate>(exportName);

        public static Pointer ResolveExport(Pointer moduleBase, int exportOrdinal)
            => new ExportResolver(moduleBase).GetExport(exportOrdinal);

        public static Pointer ResolveExport(string moduleName, int exportOrdinal)
            => new ExportResolver(moduleName).GetExport(exportOrdinal);

        public static Delegate ResolveExport(Pointer moduleBase, int exportOrdinal, Type delegateType)
            => new ExportResolver(moduleBase).GetExport(exportOrdinal, delegateType);

        public static Delegate ResolveExport(string moduleName, int exportOrdinal, Type delegateType)
            => new ExportResolver(moduleName).GetExport(exportOrdinal, delegateType);

        public static TDelegate ResolveExport<TDelegate>(Pointer moduleBase, int exportOrdinal) where TDelegate : class
            => new ExportResolver(moduleBase).GetExport<TDelegate>(exportOrdinal);

        public static TDelegate ResolveExport<TDelegate>(string moduleName, int exportOrdinal) where TDelegate : class
            => new ExportResolver(moduleName).GetExport<TDelegate>(exportOrdinal);
    }
}