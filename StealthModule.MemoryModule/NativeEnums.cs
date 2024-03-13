using System;

namespace StealthModule.MemoryModule
{
    [Flags]
    public enum AllocationType : uint
    {
        None = 0,
        COMMIT = 0x1000,
        RESERVE = 0x2000,
        DECOMMIT = 0x4000,
        RELEASE = 0x8000,
        RESET = 0x80000,
        TOP_DOWN = 0x100000,
        WRITE_WATCH = 0x200000,
        PHYSICAL = 0x400000,
        LARGE_PAGES = 0x20000000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        None = 0,
        NOACCESS = 0x01,
        READONLY = 0x02,
        READWRITE = 0x04,
        WRITECOPY = 0x08,
        EXECUTE = 0x10,
        EXECUTE_READ = 0x20,
        EXECUTE_READWRITE = 0x40,
        EXECUTE_WRITECOPY = 0x80,
        GUARD = 0x100,
        NOCACHE = 0x200,
        WRITECOMBINE = 0x400
    }

    [Flags]
    public enum SectionTypes : uint
    {
        None = 0,
        SEC_IMAGE = 0x1000000,
        SEC_RESERVE = 0x4000000,
        SEC_COMMIT = 0x08000000,
        SEC_NOCACHE = 0x10000000,
        SEC_IMAGE_NO_EXECUTE = 0x11000000,
        SEC_WRITECOMBINE = 0x40000000,
        SEC_LARGE_PAGES = 0x80000000,
    }

    [Flags]
    public enum AccessMask : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F,

        SECTION_ALL_ACCESS = 0x10000000,
        SECTION_QUERY = 0x0001,
        SECTION_MAP_WRITE = 0x0002,
        SECTION_MAP_READ = 0x0004,
        SECTION_MAP_EXECUTE = 0x0008,
        SECTION_EXTEND_SIZE = 0x0010
    };

    /// <summary>
    /// https://learn.microsoft.com/ko-kr/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa
    /// </summary>
    [Flags]
    public enum LoadLibraryFlags : uint
    {
        None = 0,
        DONT_RESOLVE_DLL_REFERENCES = 1 << 0,
        LOAD_LIBRARY_AS_DATAFILE = 1 << 1,
        LOAD_WITH_ALTERED_SEARCH_PATH = 1 << 3,
        LOAD_IGNORE_CODE_AUTHZ_LEVEL = 1 << 4,
        LOAD_LIBRARY_AS_IMAGE_RESOURCE = 1 << 5,
        LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 1 << 6,
        LOAD_LIBRARY_REQUIRE_SIGNED_TARGET = 1 << 7,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 1 << 8,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 1 << 9,
        LOAD_LIBRARY_SEARCH_USER_DIRS = 1 << 10,
        LOAD_LIBRARY_SEARCH_SYSTEM32 = 1 << 11,
        LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 1 << 12,
        LOAD_LIBRARY_SAFE_CURRENT_DIRS = 1 << 13,
    }

    /// <summary>
    /// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi/system_information_class.htm
    /// </summary>
    public enum SystemInformationClass : uint
    {
        SystemBasicInformation = 0x00,
    }


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
    public enum FileShareFlags : uint
    {
        None = 0,
        FILE_SHARE_NONE = None,
        FILE_SHARE_READ = 1 << 0,
        FILE_SHARE_WRITE = 1 << 1,
        FILE_SHARE_DELETE = 1 << 2
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

    public enum ProcessInfoClass : uint
    {
        ProcessBasicInformation = 0,
    };
}
