using System;

namespace StealthModule.MemoryModule.Native
{
    [Flags]
    public enum FileAccessFlags : uint
    {
        None = 0,
        FILE_READ_DATA = 1 << 0,
        FILE_WRITE_DATA = 1 << 1,
        FILE_APPEND_DATA = 1 << 2,
        FILE_READ_EA = 1 << 3,
        FILE_WRITE_EA = 1 << 4,
        FILE_EXECUTE = 1 << 5,
        FILE_READ_ATTRIBUTES = 1 << 7,
        FILE_WRITE_ATTRIBUTES = 1 << 8,
        DELETE = 1 << 16,
        READ_CONTROL = 1 << 17,
        WRITE_DAC = 1 << 18,
        WRITE_OWNER = 1 << 19,
        SYNCHRONIZE = 1 << 20
    }

    [Flags]
    public enum FileOpenFlags : uint
    {
        FILE_DIRECTORY_FILE = 1 << 0,
        FILE_WRITE_THROUGH = 1 << 1,
        FILE_SEQUENTIAL_ONLY = 1 << 2,
        FILE_NO_INTERMEDIATE_BUFFERING = 1 << 3,
        FILE_SYNCHRONOUS_IO_ALERT = 1 << 4,
        FILE_SYNCHRONOUS_IO_NONALERT = 1 << 5,
        FILE_NON_DIRECTORY_FILE = 1 << 6,
        FILE_CREATE_TREE_CONNECTION = 1 << 7,
        FILE_COMPLETE_IF_OPLOCKED = 1 << 8,
        FILE_NO_EA_KNOWLEDGE = 1 << 9,
        FILE_OPEN_FOR_RECOVERY = 1 << 10,
        FILE_RANDOM_ACCESS = 1 << 11,
        FILE_DELETE_ON_CLOSE = 1 << 12,
        FILE_OPEN_BY_FILE_ID = 1 << 13,
        FILE_OPEN_FOR_BACKUP_INTENT = 1 << 14,
        FILE_NO_COMPRESSION = 1 << 15
    }

    [Flags]
    public enum FileShareFlags : uint
    {
        None = 0,
        FILE_SHARE_NONE = None,
        FILE_SHARE_READ = 1 << 0,
        FILE_SHARE_WRITE = 1 << 1,
        FILE_SHARE_DELETE = 1 << 2
    }
}
