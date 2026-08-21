using System;
using System.Formats.Asn1;
using System.IO;

namespace SignService.Services;

/// <summary>
/// Перекодирование BER → определённые (definite) длины в стиле DER.
/// Реальные подписи (КриптоПро, КриптоАРМ, порталы) часто закодированы в BER
/// с неопределённой длиной (indefinite length, 0x80 … 0x00 0x00) или с длинной
/// формой длины там, где возможна короткая; ASN.1-писатель .NET такие TLV
/// не принимает. Здесь структура и порядок элементов сохраняются, пересчитываются
/// только длины; данные после первого TLV (хвост) отбрасываются.
/// </summary>
internal static class BerDer
{
    /// <summary>
    /// Возвращает первый TLV из входа, перекодированный в definite-length форму.
    /// </summary>
    public static byte[] ToDefinite(ReadOnlySpan<byte> input)
    {
        var output = new MemoryStream();
        ConvertValue(input, output);
        return output.ToArray();
    }

    // Перекодирует один TLV из s в output; возвращает число прочитанных байтов.
    private static int ConvertValue(ReadOnlySpan<byte> s, MemoryStream output)
    {
        if (s.Length < 2)
            throw new AsnContentException("Обрезанные ASN.1-данные.");

        var p = 0;
        var b0 = s[p++];
        if ((b0 & 0x1F) == 0x1F)
        {
            // многобайтовый тег
            while (p < s.Length && (s[p] & 0x80) != 0)
                p++;
            p++;
        }

        var tagLength = p;
        var constructed = (b0 & 0x20) != 0;
        if (p >= s.Length)
            throw new AsnContentException("Обрезанные ASN.1-данные (нет длины).");

        var lengthByte = s[p++];
        byte[] content;

        if (lengthByte == 0x80)
        {
            // Неопределённая длина — только для составных значений; дети идут
            // до маркера конца содержимого (EOC, 0x00 0x00).
            if (!constructed)
                throw new AsnContentException("Неопределённая длина у примитивного значения.");

            var inner = new MemoryStream();
            while (true)
            {
                if (p + 1 >= s.Length)
                    throw new AsnContentException("Не найден маркер конца содержимого (EOC).");
                if (s[p] == 0x00 && s[p + 1] == 0x00)
                {
                    p += 2;
                    break;
                }

                p += ConvertValue(s[p..], inner);
            }

            content = inner.ToArray();
        }
        else
        {
            int length;
            if (lengthByte < 0x80)
            {
                length = lengthByte;
            }
            else
            {
                var lengthBytes = lengthByte & 0x7F;
                if (lengthBytes is 0 or > 4 || p + lengthBytes > s.Length)
                    throw new AsnContentException("Некорректная длина ASN.1-значения.");
                length = 0;
                for (var i = 0; i < lengthBytes; i++)
                    length = (length << 8) | s[p++];
            }

            if (p + length > s.Length)
                throw new AsnContentException("Длина ASN.1-значения выходит за пределы данных.");

            if (constructed)
            {
                var inner = new MemoryStream();
                var children = s.Slice(p, length);
                var q = 0;
                while (q < children.Length)
                    q += ConvertValue(children[q..], inner);
                content = inner.ToArray();
            }
            else
            {
                content = s.Slice(p, length).ToArray();
            }

            p += length;
        }

        output.Write(s[..tagLength]);
        WriteLength(output, content.Length);
        output.Write(content);
        return p;
    }

    private static void WriteLength(MemoryStream output, int length)
    {
        if (length < 0x80)
        {
            output.WriteByte((byte)length);
            return;
        }

        Span<byte> buffer = stackalloc byte[4];
        var count = 0;
        var value = length;
        while (value > 0)
        {
            buffer[count++] = (byte)(value & 0xFF);
            value >>= 8;
        }

        output.WriteByte((byte)(0x80 | count));
        for (var i = count - 1; i >= 0; i--)
            output.WriteByte(buffer[i]);
    }
}
