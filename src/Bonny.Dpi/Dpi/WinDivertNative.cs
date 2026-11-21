using System.Runtime.InteropServices;

namespace Bonny.Dpi;

internal static class WinDivertNative
{
    internal const int AddressSize = 80;
    internal const uint LayerNetwork = 0;
    internal const uint ShutdownReceive = 1;
    internal static readonly IntPtr InvalidHandle = new(-1);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetDllDirectory(string path);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WinDivertOpen(string filter, uint layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WinDivertRecv(IntPtr handle, [Out] byte[] packet, uint packetLength, out uint readLength, [Out] byte[] address);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WinDivertSend(IntPtr handle, byte[] packet, uint packetLength, out uint sendLength, byte[] address);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WinDivertHelperCalcChecksums([In, Out] byte[] packet, uint packetLength, [In, Out] byte[] address, ulong flags);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WinDivertShutdown(IntPtr handle, uint how);

    [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WinDivertClose(IntPtr handle);
}
