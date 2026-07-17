using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace SignService.Services;

/// <summary>
/// Создание CMS/PKCS#7 подписи через нативный CryptoAPI (crypt32.dll), как в ReportGGE.
/// .NET SignedCms не умеет ГОСТ-алгоритмы, поэтому подпись формируется вызовом
/// CryptSignMessage — Windows передаёт операцию криптопровайдеру сертификата
/// (для ГОСТ — КриптоПро CSP), который при необходимости запросит PIN-код контейнера.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class NativeSign
{
    private const uint X509AsnEncoding = 0x00000001;
    private const uint Pkcs7AsnEncoding = 0x00010000;
    private const uint MsgEncoding = X509AsnEncoding | Pkcs7AsnEncoding;

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptObjidBlob
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct CryptAlgorithmIdentifier
    {
        [MarshalAs(UnmanagedType.LPStr)] public string pszObjId;
        public CryptObjidBlob Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptSignMessagePara
    {
        public uint cbSize;
        public uint dwMsgEncodingType;
        public IntPtr pSigningCert;              // PCCERT_CONTEXT
        public CryptAlgorithmIdentifier HashAlgorithm;
        public IntPtr pvHashAuxInfo;
        public uint cMsgCert;
        public IntPtr rgpMsgCert;                // PCCERT_CONTEXT*
        public uint cMsgCrl;
        public IntPtr rgpMsgCrl;
        public uint cAuthAttr;
        public IntPtr rgAuthAttr;
        public uint cUnauthAttr;
        public IntPtr rgUnauthAttr;
        public uint dwFlags;
        public uint dwInnerContentType;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptSignMessage(
        ref CryptSignMessagePara pSignPara,
        [MarshalAs(UnmanagedType.Bool)] bool fDetachedSignature,
        uint cToBeSigned,
        IntPtr[] rgpbToBeSigned,
        uint[] rgcbToBeSigned,
        byte[]? pbSignedBlob,
        ref uint pcbSignedBlob);

    /// <summary>
    /// Подписывает данные сертификатом, вкладывая в подпись переданные сертификаты
    /// (лист + цепочка УЦ — для офлайн-проверки, как это делает портал).
    /// </summary>
    /// <param name="hashOid">OID алгоритма хеширования, соответствующий ключу сертификата.</param>
    /// <param name="detached">true — откреплённая подпись; false — документ внутри.</param>
    public static byte[] Sign(
        byte[] data,
        X509Certificate2 signerCert,
        IReadOnlyList<X509Certificate2> embedCerts,
        string hashOid,
        bool detached)
    {
        var dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
        // Массив PCCERT_CONTEXT вкладываемых сертификатов; сами объекты X509Certificate2
        // должны жить до конца вызова — за это отвечает вызывающий.
        var certPtrs = new IntPtr[embedCerts.Count];
        for (var i = 0; i < embedCerts.Count; i++)
            certPtrs[i] = embedCerts[i].Handle;
        var certArrayHandle = GCHandle.Alloc(certPtrs, GCHandleType.Pinned);

        try
        {
            var para = new CryptSignMessagePara
            {
                cbSize = (uint)Marshal.SizeOf<CryptSignMessagePara>(),
                dwMsgEncodingType = MsgEncoding,
                pSigningCert = signerCert.Handle,
                HashAlgorithm = new CryptAlgorithmIdentifier { pszObjId = hashOid },
                cMsgCert = (uint)certPtrs.Length,
                rgpMsgCert = certPtrs.Length > 0 ? certArrayHandle.AddrOfPinnedObject() : IntPtr.Zero,
            };

            var toSign = new[] { dataHandle.AddrOfPinnedObject() };
            var lengths = new[] { (uint)data.Length };

            uint size = 0;
            if (!CryptSignMessage(ref para, detached, 1, toSign, lengths, null, ref size))
                throw NewSignError();

            var blob = new byte[size];
            if (!CryptSignMessage(ref para, detached, 1, toSign, lengths, blob, ref size))
                throw NewSignError();

            if (size != blob.Length)
                Array.Resize(ref blob, (int)size);
            return blob;
        }
        finally
        {
            dataHandle.Free();
            certArrayHandle.Free();
            GC.KeepAlive(signerCert);
            GC.KeepAlive(embedCerts);
        }
    }

    private static Exception NewSignError()
    {
        var error = Marshal.GetLastWin32Error();
        var inner = new Win32Exception(error);
        var hint = (uint)error switch
        {
            0x80090008 => " Криптопровайдер не поддерживает алгоритм — для ГОСТ-сертификата должен быть установлен КриптоПро CSP.", // NTE_BAD_ALGID
            0x8009000D => " Закрытый ключ недоступен — проверьте контейнер ключа.",                                                  // NTE_NO_KEY
            0x8010006E => " Ввод PIN-кода отменён пользователем.",                                                                   // SCARD_W_CANCELLED_BY_USER
            _ => string.Empty,
        };
        return new InvalidOperationException($"CryptSignMessage: {inner.Message} (0x{error:X8}).{hint}", inner);
    }
}
