using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SignService.Services;

/// <summary>
/// Клиент службы штампов времени (TSA, RFC 3161) для усовершенствованной подписи
/// CAdES-T: значение подписи хешируется, хеш отправляется в TSA, полученный
/// штамп времени (TimeStampToken) вкладывается в подпись неподписанным атрибутом.
/// Для ГОСТ-подписей хеш считается Стрибогом (своей реализацией), поэтому клиент
/// работает и без КриптоПро; TSA-сервер должен поддерживать соответствующий алгоритм.
/// </summary>
public class TimestampClient
{
    /// <summary>OID неподписанного атрибута timeStampToken (RFC 3161 / CAdES-T).</summary>
    public const string TimeStampTokenOid = "1.2.840.113549.1.9.16.2.14";

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    /// <summary>
    /// Запрашивает у TSA штамп времени на значение подписи.
    /// </summary>
    /// <param name="signatureValue">Байты значения подписи (поле signature из SignerInfo).</param>
    /// <param name="gost">true — хешировать Стрибогом (ГОСТ Р 34.11-2012-256), иначе SHA-256.</param>
    /// <param name="tsaUrl">Адрес службы штампов времени.</param>
    /// <returns>DER-байты TimeStampToken (ContentInfo/SignedData) для неподписанного атрибута.</returns>
    public virtual async Task<byte[]> RequestTokenAsync(
        byte[] signatureValue, bool gost, string tsaUrl, CancellationToken cancellationToken = default)
    {
        byte[] hash;
        string hashOid;
        if (gost)
        {
            hash = Streebog.Hash256(signatureValue);
            hashOid = "1.2.643.7.1.1.2.2";
        }
        else
        {
            hash = SHA256.HashData(signatureValue);
            hashOid = "2.16.840.1.101.3.4.2.1";
        }

        var nonce = new byte[8];
        RandomNumberGenerator.Fill(nonce);
        // старший байт без знакового бита — некоторые TSA не принимают отрицательный nonce
        nonce[0] &= 0x7F;

        var request = System.Security.Cryptography.Pkcs.Rfc3161TimestampRequest.CreateFromHash(
            hash,
            new Oid(hashOid),
            nonce: nonce,
            requestSignerCertificates: true);

        using var content = new ByteArrayContent(request.Encode());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        HttpResponseMessage response;
        try
        {
            response = await Http.PostAsync(tsaUrl, content, cancellationToken);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            throw new InvalidOperationException(
                $"Служба штампов времени недоступна ({tsaUrl}): {e.Message}", e);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Служба штампов времени вернула ошибку HTTP {(int)response.StatusCode} ({tsaUrl}).");

            var body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            try
            {
                var token = request.ProcessResponse(body, out _);
                return token.AsSignedCms().Encode();
            }
            catch (CryptographicException e)
            {
                throw new InvalidOperationException(
                    "Служба штампов времени вернула некорректный ответ: " + e.Message, e);
            }
        }
    }
}
