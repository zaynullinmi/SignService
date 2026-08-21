using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using PdfSharp.Drawing;
using PdfSharp.Fonts;
using PdfSharp.Pdf;
using PdfSharp.Pdf.IO;

namespace SignService.Services;

/// <summary>
/// Визуальный штамп о подписании на PDF-документе: плашка «Документ подписан
/// электронной подписью» с данными сертификата, датой (по желанию) и логотипом
/// организации. Штамп ставится в правом нижнем углу последней страницы.
/// Важно: штампованная копия создаётся ДО подписания и подписывается именно она —
/// иначе подпись не соответствовала бы изменённому файлу.
/// </summary>
public static class PdfStamper
{
    static PdfStamper()
    {
        GlobalFontSettings.FontResolver ??= new EmbeddedFontResolver();
    }

    public static bool IsPdf(string filePath) =>
        Path.GetExtension(filePath).Equals(".pdf", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Создаёт штампованную копию PDF. Возвращает путь к копии
    /// («имя (со штампом).pdf» рядом с исходным файлом; существующая копия обновляется).
    /// </summary>
    public static string CreateStampedCopy(
        string pdfPath,
        X509Certificate2 certificate,
        bool withDate,
        string? logoPath,
        DateTime signTime,
        string? poaNumber = null)
        => CreateStampedCopy(pdfPath, new[] { certificate }, withDate, logoPath, signTime, poaNumber);

    /// <summary>
    /// Штампованная копия с несколькими подписантами (по блоку данных на каждого) —
    /// используется в режиме «копия отдельно», когда штамп отражает всех
    /// подписантов итоговой подписи.
    /// </summary>
    public static string CreateStampedCopy(
        string pdfPath,
        IReadOnlyList<X509Certificate2> certificates,
        bool withDate,
        string? logoPath,
        DateTime signTime,
        string? poaNumber = null)
    {
        if (certificates.Count == 0)
            throw new ArgumentException("Нет сертификатов для штампа.", nameof(certificates));

        var directory = Path.GetDirectoryName(pdfPath) ?? ".";
        var stem = Path.GetFileNameWithoutExtension(pdfPath);
        var outputPath = Path.Combine(directory, $"{stem} (со штампом).pdf");

        using var document = PdfReader.Open(pdfPath, PdfDocumentOpenMode.Modify);
        var page = document.Pages[document.Pages.Count - 1];
        using (var gfx = XGraphics.FromPdfPage(page))
        {
            DrawStamp(gfx, page, certificates, withDate, logoPath, signTime, poaNumber);
        }

        document.Save(outputPath);
        return outputPath;
    }

    private static void DrawStamp(
        XGraphics gfx, PdfPage page, IReadOnlyList<X509Certificate2> certificates,
        bool withDate, string? logoPath, DateTime signTime, string? poaNumber)
    {
        const double width = 250;
        const double margin = 20;
        var blue = XColor.FromArgb(0x1B, 0x4F, 0x9C);
        var pen = new XPen(blue, 1.2);
        var titleFont = new XFont("stamp", 8, XFontStyleEx.Bold);
        var textFont = new XFont("stamp", 7, XFontStyleEx.Regular);

        // Содержимое: блок на каждого подписанта, затем общие строки
        var lines = new List<string>();
        for (var i = 0; i < certificates.Count; i++)
        {
            var c = certificates[i];
            if (certificates.Count > 1)
                lines.Add($"Подписант {i + 1}:");
            lines.Add($"Сертификат: {c.SerialNumber}");
            lines.Add($"Владелец: {CertificateProvider.GetSubjectName(c)}");
            lines.Add($"Действителен: с {c.NotBefore:dd.MM.yyyy} по {c.NotAfter:dd.MM.yyyy}");
        }

        if (!string.IsNullOrWhiteSpace(poaNumber))
            lines.Add($"Действует на основании МЧД № {poaNumber}");
        var dateLine = withDate ? $"Дата подписания: {signTime:dd.MM.yyyy HH:mm}" : null;

        const double pad = 8;
        const double lineHeight = 10.5;
        const double titleHeight = 24;
        var logoSize = logoPath is not null ? 34.0 : 0.0;
        var bodyLines = lines.Count + (dateLine is null ? 0 : 1);
        var height = pad * 2 + Math.Max(titleHeight, logoSize) + 4 + bodyLines * lineHeight;

        var x = page.Width.Point - width - margin;
        var y = page.Height.Point - height - margin;
        var rect = new XRect(x, y, width, height);

        // Фон и рамка со скруглением
        gfx.DrawRoundedRectangle(pen, XBrushes.White, rect, new XSize(8, 8));

        var contentX = x + pad;
        var topY = y + pad;

        // Логотип
        if (logoPath is not null && LoadLogo(logoPath) is { } logo)
        {
            using (logo)
            {
                var scale = logoSize / Math.Max(logo.PixelWidth, logo.PixelHeight);
                var w = logo.PixelWidth * scale;
                var h = logo.PixelHeight * scale;
                gfx.DrawImage(logo, contentX, topY + (logoSize - h) / 2, w, h);
            }

            contentX += logoSize + 8;
        }

        // Заголовок
        var titleRect = new XRect(contentX, topY, x + width - pad - contentX, titleHeight + 4);
        gfx.DrawString("ДОКУМЕНТ ПОДПИСАН", titleFont, new XSolidBrush(blue),
            new XRect(titleRect.X, titleRect.Y, titleRect.Width, 12), XStringFormats.TopLeft);
        gfx.DrawString("ЭЛЕКТРОННОЙ ПОДПИСЬЮ", titleFont, new XSolidBrush(blue),
            new XRect(titleRect.X, titleRect.Y + 11, titleRect.Width, 12), XStringFormats.TopLeft);

        // Текст
        var textBrush = new XSolidBrush(blue);
        var textY = topY + Math.Max(titleHeight, logoSize) + 4;
        foreach (var line in dateLine is null ? lines : lines.Append(dateLine))
        {
            gfx.DrawString(Truncate(gfx, line, textFont, width - pad * 2), textFont, textBrush,
                new XRect(x + pad, textY, width - pad * 2, lineHeight), XStringFormats.TopLeft);
            textY += lineHeight;
        }
    }

    // PDFsharp (Core) сам декодирует не все форматы (PNG — нет), поэтому логотип
    // при необходимости перекодируется через SkiaSharp в JPEG на белом фоне.
    private static XImage? LoadLogo(string path)
    {
        try
        {
            return XImage.FromFile(path);
        }
        catch (Exception)
        {
            // формат не поддержан напрямую — пробуем через SkiaSharp
        }

        try
        {
            using var bitmap = SkiaSharp.SKBitmap.Decode(path);
            if (bitmap is null)
                return null;

            using var surface = SkiaSharp.SKSurface.Create(
                new SkiaSharp.SKImageInfo(bitmap.Width, bitmap.Height));
            surface.Canvas.Clear(SkiaSharp.SKColors.White);
            surface.Canvas.DrawBitmap(bitmap, 0, 0);
            using var snapshot = surface.Snapshot();
            using var encoded = snapshot.Encode(SkiaSharp.SKEncodedImageFormat.Jpeg, 92);
            // поток остаётся у XImage — не освобождаем его здесь
            return XImage.FromStream(new MemoryStream(encoded.ToArray()));
        }
        catch (Exception)
        {
            return null; // логотип не читается — штамп будет без него
        }
    }

    private static string Truncate(XGraphics gfx, string text, XFont font, double maxWidth)
    {
        if (gfx.MeasureString(text, font).Width <= maxWidth)
            return text;
        while (text.Length > 1 && gfx.MeasureString(text + "…", font).Width > maxWidth)
            text = text[..^1];
        return text + "…";
    }

    /// <summary>Кириллический шрифт для штампа из ресурсов приложения (DejaVu Sans).</summary>
    private sealed class EmbeddedFontResolver : IFontResolver
    {
        public byte[]? GetFont(string faceName)
        {
            var resource = faceName switch
            {
                "stamp#b" => "SignService.Assets.Fonts.DejaVuSans-Bold.ttf",
                _ => "SignService.Assets.Fonts.DejaVuSans.ttf",
            };

            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)
                ?? throw new InvalidOperationException($"Не найден ресурс шрифта {resource}.");
            using var memory = new MemoryStream();
            stream.CopyTo(memory);
            return memory.ToArray();
        }

        public FontResolverInfo? ResolveTypeface(string familyName, bool bold, bool italic) =>
            new(bold ? "stamp#b" : "stamp#r");
    }
}
