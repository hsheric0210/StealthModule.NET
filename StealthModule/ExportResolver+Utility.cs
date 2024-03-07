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

        public static Pointer ResolveExport(Pointer moduleBase, short exportOrdinal)
            => new ExportResolver(moduleBase).GetExport(exportOrdinal);

        public static Pointer ResolveExport(string moduleName, short exportOrdinal)
            => new ExportResolver(moduleName).GetExport(exportOrdinal);
    }
}