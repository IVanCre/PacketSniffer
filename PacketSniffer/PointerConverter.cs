using System;
using System.Runtime.InteropServices;

namespace PacketSniffer
{
    public static class PointerConverter
    {
        public static IntPtr ToIntPtr(this object target) 
        {
            GCHandle handle1 = GCHandle.Alloc(target);
            IntPtr ptr = (IntPtr)handle1;
            return ptr;
        }

        public static object ToObject(IntPtr ptr)
        {
            GCHandle handle2 = (GCHandle)ptr;
            return handle2.Target;
        }
    }
}
