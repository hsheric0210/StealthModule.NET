using System;
using System.Runtime.InteropServices;

namespace StealthModule
{
    /// <summary>
    /// A wrapper class for UIntPtr to provide additional pointer arithmetic, alignment and checks.
    /// </summary>
    public readonly struct Pointer
    {
        public static readonly Pointer Zero = new Pointer(IntPtr.Zero);

        public static int Size => IntPtr.Size;

        public static bool Is64Bit => Size == 8;

        private readonly IntPtr value;

        private Pointer(IntPtr value) => this.value = value;

        // (Auto-)Boxing functions (object -> Pointer)

        public static implicit operator Pointer(IntPtr value) => new Pointer(value);
        public static implicit operator Pointer(UIntPtr value) => new Pointer((IntPtr)ToInt64(value));
        public static explicit operator Pointer(long value) => new Pointer((IntPtr)value);
        public static explicit operator Pointer(ulong value) => new Pointer((IntPtr)unchecked((long)value));
        public static explicit operator Pointer(int value) => new Pointer((IntPtr)value);
        public static explicit operator Pointer(uint value) => new Pointer((IntPtr)unchecked((int)value));

        // (Auto-)Unboxing functions (Pointer -> object)

        public static implicit operator IntPtr(Pointer value) => value.value;
        public static implicit operator UIntPtr(Pointer value) => new UIntPtr(ToUInt64(value.value));
        public static explicit operator int(Pointer value) => ToInt32(value.value);
        public static explicit operator uint(Pointer value) => ToUInt32(value.value);
        public static explicit operator long(Pointer value) => ToInt64(value.value);
        public static explicit operator ulong(Pointer value) => ToUInt64(value.value);

        // Direct read/write

        public T Read<T>() => (T)Marshal.PtrToStructure(this, typeof(T));

        public Pointer Read() => (Pointer)(IntPtr)Marshal.PtrToStructure(this, typeof(IntPtr));

        public void Write<T>(T buffer) => Marshal.StructureToPtr(buffer, this, false);
        public void Write(Pointer buffer) => Marshal.StructureToPtr((IntPtr)buffer, this, false);

        // Pointer arithmetics - Add

        public static Pointer operator +(Pointer value, Pointer offset)
            => value + offset.value;

        public static Pointer operator +(Pointer value, IntPtr offset)
            => Is64Bit
                ? (Pointer)(ToInt64(value.value) + ToInt64(offset))
                : (Pointer)(ToInt32(value.value) + ToInt32(offset));

        public static Pointer operator +(Pointer value, UIntPtr offset)
            => Is64Bit
                ? (Pointer)(ToInt64(value.value) + ToInt64(offset))
                : (Pointer)(ToInt32(value.value) + ToInt32(offset));

        public static Pointer operator +(Pointer value, int offset)
            => (Pointer)(value.value.ToInt64() + offset);

        public static Pointer operator +(Pointer value, uint offset)
            => Is64Bit
                ? (Pointer)(ToInt64(value.value) + offset)
                : (Pointer)(ToInt32(value.value) + unchecked((int)offset));

        // Pointer arithmetics - Subtract

        public static Pointer operator -(Pointer value, Pointer offset)
            => value - offset.value;

        public static Pointer operator -(Pointer value, IntPtr offset)
            => Is64Bit
                ? (Pointer)(ToInt64(value.value) - ToInt64(offset))
                : (Pointer)(ToInt32(value.value) - ToInt32(offset));

        public static Pointer operator -(Pointer value, UIntPtr offset)
            => Is64Bit
                ? (Pointer)(ToInt64(value.value) - ToInt64(offset))
                : (Pointer)(ToInt32(value.value) - ToInt32(offset));

        public static Pointer operator -(Pointer value, int offset)
            => (Pointer)(ToInt64(value.value) - offset);

        public static Pointer operator -(Pointer value, uint offset)
            => Is64Bit
                ? (Pointer)(ToInt64(value.value) - offset)
                : (Pointer)(ToInt32(value.value) - unchecked((int)offset));

        // Bitwise operations

        public static Pointer operator &(Pointer value, Pointer v)
            => value & v.value;

        public static Pointer operator &(Pointer value, IntPtr v)
            => Is64Bit
                ? (Pointer)(ToUInt64(value.value) & ToUInt64(v))
                : (Pointer)(ToUInt32(value.value) & ToUInt32(v));

        public static Pointer operator &(Pointer value, UIntPtr v)
            => Is64Bit
                ? (Pointer)(ToUInt64(value.value) & ToUInt64(v))
                : (Pointer)(ToUInt32(value.value) & ToUInt32(v));

        public static Pointer operator |(Pointer value, Pointer v)
            => value | v.value;

        public static Pointer operator |(Pointer value, IntPtr v)
            => Is64Bit
                ? (Pointer)(ToUInt64(value.value) | ToUInt64(v))
                : (Pointer)(ToUInt32(value.value) | ToUInt32(v));

        public static Pointer operator |(Pointer value, UIntPtr v)
            => Is64Bit
                ? (Pointer)(ToUInt64(value.value) | ToUInt64(v))
                : (Pointer)(ToUInt32(value.value) | ToUInt32(v));

        public static Pointer operator ^(Pointer value, Pointer v)
            => value ^ v.value;

        public static Pointer operator ^(Pointer value, IntPtr v)
            => Is64Bit
                ? (Pointer)(ToUInt64(value.value) ^ ToUInt64(v))
                : (Pointer)(ToUInt32(value.value) ^ ToUInt32(v));

        public static Pointer operator ^(Pointer value, UIntPtr v)
            => Is64Bit
                ? (Pointer)(ToUInt64(value.value) ^ ToUInt64(v))
                : (Pointer)(ToUInt32(value.value) ^ ToUInt32(v));

        // Align

        public Pointer AlignDown(UIntPtr align)
            => (Pointer)unchecked((long)(ToUInt64(value) & ~(ToUInt64(align) - 1)));

        public bool SpanBoundary(uint Size, int BoundaryBits)
            => unchecked((ulong)value.ToInt64()) >> BoundaryBits < (ToUInt64(value) + Size) >> BoundaryBits;

        public bool IsInvalidHandle()
            => value == IntPtr.Zero
            || value == (Is64Bit
                ? (IntPtr)(long)-1
                : (IntPtr)(-1));

        // Comparison operator

        public static bool operator ==(Pointer value1, Pointer value2) => value1.value == value2.value;

        public static bool operator !=(Pointer value1, Pointer value2) => value1.value != value2.value;

        public override string ToString() => Is64Bit ? ((ulong)value).ToString("X16") : ((uint)value).ToString("X8");

        public override bool Equals(object obj) => obj is Pointer other && value == other.value;

        public override int GetHashCode() => (int)this;

        private static int ToInt32(IntPtr value) => value.ToInt32();
        private static int ToInt32(UIntPtr value) => unchecked((int)value.ToUInt32());
        private static long ToInt64(IntPtr value) => value.ToInt64();
        private static long ToInt64(UIntPtr value) => unchecked((long)value.ToUInt64());
        private static uint ToUInt32(IntPtr value) => unchecked((uint)value.ToInt32());
        private static uint ToUInt32(UIntPtr value) => value.ToUInt32();
        private static ulong ToUInt64(IntPtr value) => unchecked((ulong)value.ToInt64());
        private static ulong ToUInt64(UIntPtr value) => value.ToUInt64();
    }
}
