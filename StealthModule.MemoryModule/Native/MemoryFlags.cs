using System;

namespace StealthModule.MemoryModule.Native
{
    [Flags]
    public enum AllocationType : uint
    {
        None = 0,
        COMMIT = 1 << 12,
        RESERVE = 1 << 13,
        DECOMMIT = 1 << 14,
        RELEASE = 1 << 15,
        RESET = 1 << 19,
        TOP_DOWN = 1 << 20,
        WRITE_WATCH = 1 << 21,
        PHYSICAL = 1 << 22,
        LARGE_PAGES = 1 << 29
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        None = 0,
        NOACCESS = 1 << 0,
        READONLY = 1 << 1,
        READWRITE = 1 << 2,
        WRITECOPY = 1 << 3,
        EXECUTE = 1 << 4,
        EXECUTE_READ = 1 << 5,
        EXECUTE_READWRITE = 1 << 6,
        EXECUTE_WRITECOPY = 1 << 7,
        GUARD = 1 << 8,
        NOCACHE = 1 << 9,
        WRITECOMBINE = 1 << 10
    }
}
