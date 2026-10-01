using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

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
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
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

        var generator = new TimeStampRequestGenerator();
        generator.SetCertReq(true);
        var request = generator.Generate(hashOid, hash, new BigInteger(1, nonce));

        using var content = new ByteArrayContent(request.GetEncoded());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        HttpResponseMessage response;
        try
        {
            using var httpRequest = new HttpRequestMessage(HttpMethod.Post, tsaUrl) { Content = content };
            response = await Http.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
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

            const int maxBytes = 4 * 1024 * 1024;
            if (response.Content.Headers.ContentLength > maxBytes)
                throw new InvalidOperationException("Ответ TSA превышает допустимый размер.");
            await using var input = await response.Content.ReadAsStreamAsync(deadline.Token);
            using var output = new MemoryStream();
            var buffer = new byte[8192];
            int count;
            while ((count = await input.ReadAsync(buffer, deadline.Token)) != 0)
            {
                if (output.Length + count > maxBytes) throw new InvalidOperationException("Ответ TSA превышает допустимый размер.");
                output.Write(buffer, 0, count);
            }
            try
            {
                return ValidateResponse(output.ToArray(), request, signatureValue);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                throw new InvalidOperationException(
                    "Служба штампов времени вернула некорректный ответ: " + e.Message, e);
            }
        }
    }

    internal static byte[] ValidateResponse(byte[] responseBytes, TimeStampRequest request, byte[] signatureValue)
    {
        var response = new TimeStampResponse(responseBytes);
        response.Validate(request); // status, nonce, policy, digest algorithm and message imprint
        var token = response.TimeStampToken ?? throw new CryptographicException("TSA не вернула метку времени.");
        var encoded = token.GetEncoded();
        var check = SignatureVerifier.VerifyTimestampToken(encoded, signatureValue, VerificationOptions.CryptographyOnly);
        if (check.Check.State != VerificationState.Valid) throw new CryptographicException(check.Check.Message);
        // This proves token integrity. TSA trust/revocation is a separate result in the verification report.
        return encoded;
    }
}
