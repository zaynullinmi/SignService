using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace SignService.Services;

/// <summary>Криптографическая проверка всех подписантов; доверие УЦ и отзыв проверяются отдельно.</summary>
internal static class CmsVerifier
{
    public static void VerifyDocument(byte[] signature, byte[] document)
    {
        var normalized = CmsMerger.Normalize(signature);
        var embedded = CmsMerger.ExtractContent(normalized);
        if (embedded is not null && !embedded.AsSpan().SequenceEqual(document))
            throw new CryptographicException("Вложенный документ не соответствует файлу МЧД.");
        var signers = CmsMerger.SplitBySigner(normalized);
        if (signers.Count == 0)
            throw new CryptographicException("В файле нет подписантов.");

        // Проверяем каждый исходный SignerInfo, включая повторные записи одного SID.
        foreach (var (_, detached) in signers)
        {
            if (OperatingSystem.IsWindows())
            {
                // CryptoAPI передаёт ГОСТ-проверку установленному CSP, как и подписание.
                NativeSign.VerifyDetached(detached, document, 0);
            }
            else
            {
                var cms = new SignedCms(new ContentInfo(document), detached: true);
                cms.Decode(detached);
                cms.CheckSignature(verifySignatureOnly: true);
            }
        }
    }
}
