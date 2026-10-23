using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

#nullable enable
namespace AdDiag;

// The two things the SMB tab asks of Windows that .NET doesn't wrap: the first step of an SSPI sign-in, and
// listing a share. Both run as the signed-in user and change nothing.
static class SmbNative
{
    [StructLayout(LayoutKind.Sequential)]
    struct SecHandle
    {
        public IntPtr Lower, Upper;
        public readonly bool IsSet => Lower != IntPtr.Zero || Upper != IntPtr.Zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SecBuffer
    {
        public int Size, Type;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SecBufferDesc
    {
        public int Version, Count;
        public IntPtr Buffers;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct NegotiationInfo
    {
        public IntPtr PackageInfo;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PackageInfo
    {
        public uint Capabilities;
        public ushort Version, RpcId;
        public uint MaxToken;
        public IntPtr Name, Comment;
    }

    const int CredOutbound = 2, NativeDataRep = 0x10, TokenBuffer = 2, AttrNegotiationInfo = 12;
    // ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION, as an SMB client asks
    const int RequestFlags = 0x2 | 0x100 | 0x800;

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    static extern int AcquireCredentialsHandleW(string? principal, string package, int credentialUse, IntPtr logonId,
        IntPtr authData, IntPtr getKeyFn, IntPtr getKeyArgument, ref SecHandle credential, out long expiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    static extern int InitializeSecurityContextW(ref SecHandle credential, IntPtr context, string target, int flags,
        int reserved1, int dataRep, IntPtr input, int reserved2, ref SecHandle newContext, ref SecBufferDesc output,
        out int attributes, out long expiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    static extern int QueryContextAttributesW(ref SecHandle context, int attribute, out NegotiationInfo info);

    [DllImport("secur32.dll")]
    static extern int FreeContextBuffer(IntPtr buffer);

    [DllImport("secur32.dll")]
    static extern int DeleteSecurityContext(ref SecHandle context);

    [DllImport("secur32.dll")]
    static extern int FreeCredentialsHandle(ref SecHandle credential);

    /// <summary>
    /// Builds the first token of a sign-in to <paramref name="spn"/> and throws it away. With Kerberos that asks
    /// the KDC for the service ticket (cached in memory, as any connection would); with Negotiate it shows whether
    /// Windows would pick Kerberos or fall back to NTLM. The user's own credentials, none supplied or stored.
    /// </summary>
    public static SspiResult Authenticate(string package, string spn)
    {
        var credential = new SecHandle();
        var context = new SecHandle();
        var buffer = new SecBuffer { Type = TokenBuffer };
        IntPtr bufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>());
        try
        {
            int status = AcquireCredentialsHandleW(null, package, CredOutbound, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref credential, out _);
            if (status != 0) return new(status, null);

            Marshal.StructureToPtr(buffer, bufferPtr, false);
            var output = new SecBufferDesc { Version = 0, Count = 1, Buffers = bufferPtr };
            status = InitializeSecurityContextW(ref credential, IntPtr.Zero, spn, RequestFlags, 0, NativeDataRep, IntPtr.Zero, 0,
                ref context, ref output, out _, out _);
            buffer = Marshal.PtrToStructure<SecBuffer>(bufferPtr);
            if (status is not (SspiResult.Ok or SspiResult.ContinueNeeded) || package != "Negotiate")
                return new(status, null);

            string? chosen = null;
            if (QueryContextAttributesW(ref context, AttrNegotiationInfo, out var info) == 0 && info.PackageInfo != IntPtr.Zero)
            {
                var pkg = Marshal.PtrToStructure<PackageInfo>(info.PackageInfo);
                chosen = Marshal.PtrToStringUni(pkg.Name);
                FreeContextBuffer(info.PackageInfo);
            }
            return new(status, chosen);
        }
        finally
        {
            // The token is never sent; free it, the context and the credential handle
            if (buffer.Buffer != IntPtr.Zero) FreeContextBuffer(buffer.Buffer);
            Marshal.FreeHGlobal(bufferPtr);
            if (context.IsSet) DeleteSecurityContext(ref context);
            if (credential.IsSet) FreeCredentialsHandle(ref credential);
        }
    }

    /// <summary>The most entries counted in a share's root; a huge share isn't listed in full.</summary>
    public const int MaxEntries = 1000;

    /// <summary>Counts a share's root entries, up to <see cref="MaxEntries"/>, or returns the Win32 error.</summary>
    public static ShareOpen OpenShare(string unc)
    {
        try
        {
            return new(Directory.EnumerateFileSystemEntries(unc).Take(MaxEntries).Count(), 0, "");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A Win32 error arrives as HRESULT 0x8007xxxx; its low word is the error number, which isn't translated
            int hr = ex.HResult;
            int error = (hr & unchecked((int)0xFFFF0000)) == unchecked((int)0x80070000) ? hr & 0xFFFF : hr;
            return new(null, error, ex.Message);
        }
    }
}
