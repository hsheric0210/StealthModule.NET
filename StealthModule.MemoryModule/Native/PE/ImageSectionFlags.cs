namespace StealthModule.MemoryModule.Native.PE
{
    public enum ImageSectionFlags : uint
    {
        IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,  // Section contains extended relocations.
        IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,  // Section can be discarded.
        IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,  // Section is not cachable.
        IMAGE_SCN_MEM_NOT_PAGED = 0x08000000, // Section is not pageable.
        IMAGE_SCN_MEM_SHARED = 0x10000000,  // Section is shareable.
        IMAGE_SCN_MEM_EXECUTE = 0x20000000, // Section is executable.
        IMAGE_SCN_MEM_READ = 0x40000000, // Section is readable.
        IMAGE_SCN_MEM_WRITE = 0x80000000  // Section is writeable.
    }
}
