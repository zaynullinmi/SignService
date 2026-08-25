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

    /// <summary>На каких страницах ставить штампы.</summary>
    public enum StampPages
    {
        Last,
        First,
        All,
        Custom,
    }

    /// <summary>Параметры визуального штампа.</summary>
    public sealed record StampOptions
    {
        public bool WithDate { get; init; } = true;

        public string? LogoPath { get; init; }

        public string? PoaNumber { get; init; }

        public StampPages Pages { get; init; } = StampPages.Last;

        /// <summary>Номера страниц для режима Custom, например «1,3-5».</summary>
        public string? CustomPages { get; init; }
    }

    /// <summary>Совместимая обёртка: один подписант, штамп на последней странице.</summary>
    public static string CreateStampedCopy(
        string pdfPath,
        X509Certificate2 certificate,
        bool withDate,
        string? logoPath,
        DateTime signTime,
        string? poaNumber = null)
        => CreateStampedCopy(pdfPath, new[] { certificate },
            new StampOptions { WithDate = withDate, LogoPath = logoPath, PoaNumber = poaNumber }, signTime);

    /// <summary>Совместимая обёртка: несколько подписантов, последняя страница.</summary>
    public static string CreateStampedCopy(
        string pdfPath,
        IReadOnlyList<X509Certificate2> certificates,
        bool withDate,
        string? logoPath,
        DateTime signTime,
        string? poaNumber = null)
        => CreateStampedCopy(pdfPath, certificates,
            new StampOptions { WithDate = withDate, LogoPath = logoPath, PoaNumber = poaNumber }, signTime);

    /// <summary>
    /// Создаёт штампованную копию «имя (со штампом).pdf» (существующая обновляется):
    /// на выбранных страницах — ОТДЕЛЬНАЯ плашка на каждого подписанта
    /// (колонками из правого нижнего угла).
    /// </summary>
    public static string CreateStampedCopy(
        string pdfPath,
        IReadOnlyList<X509Certificate2> certificates,
        StampOptions options,
        DateTime signTime)
    {
        if (certificates.Count == 0)
            throw new ArgumentException("Нет сертификатов для штампа.", nameof(certificates));

        var directory = Path.GetDirectoryName(pdfPath) ?? ".";
        var stem = Path.GetFileNameWithoutExtension(pdfPath);
        var outputPath = Path.Combine(directory, $"{stem} (со штампом).pdf");

        using var document = PdfReader.Open(pdfPath, PdfDocumentOpenMode.Modify);
        foreach (var pageIndex in ResolvePages(options, document.Pages.Count))
        {
            var page = document.Pages[pageIndex];
            using var gfx = XGraphics.FromPdfPage(page);
            DrawStampsOnPage(gfx, page, certificates, options, signTime);
        }

        document.Save(outputPath);
        return outputPath;
    }

    /// <summary>Индексы страниц (0-based) по выбранному режиму; «1,3-5» — как в диалогах печати.</summary>
    public static IReadOnlyList<int> ResolvePages(StampOptions options, int pageCount)
    {
        switch (options.Pages)
        {
            case StampPages.First:
                return new[] { 0 };
            case StampPages.All:
                return Enumerable.Range(0, pageCount).ToArray();
            case StampPages.Custom:
                var result = new SortedSet<int>();
                foreach (var part in (options.CustomPages ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    var range = part.Split('-', 2, StringSplitOptions.TrimEntries);
                    if (!int.TryParse(range[0], out var from))
                        throw new InvalidOperationException($"Непонятный номер страницы «{part}» — укажите, например: 1,3-5.");
                    var to = from;
                    if (range.Length == 2 && !int.TryParse(range[1], out to))
                        throw new InvalidOperationException($"Непонятный диапазон страниц «{part}».");
                    for (var p = Math.Max(1, from); p <= Math.Min(pageCount, to); p++)
                        result.Add(p - 1);
                }

                if (result.Count == 0)
                    throw new InvalidOperationException(
                        $"В документе {pageCount} стр., а указанные страницы «{options.CustomPages}» не найдены.");
                return result.ToArray();
            default:
                return new[] { pageCount - 1 };
        }
    }

    // Раскладка: плашки подписантов колонками из правого нижнего угла вверх,
    // при нехватке высоты — следующая колонка левее.
    private static void DrawStampsOnPage(
        XGraphics gfx, PdfPage page, IReadOnlyList<X509Certificate2> certificates,
        StampOptions options, DateTime signTime)
    {
        const double width = 250;
        const double margin = 20;
        const double gap = 8;

        var x = page.Width.Point - width - margin;
        var y = page.Height.Point - margin;

        foreach (var certificate in certificates)
        {
            var height = ComputeStampHeight(certificate, options);
            if (y - height < margin && y < page.Height.Point - margin)
            {
                // колонка заполнена — следующая левее
                x -= width + gap;
                y = page.Height.Point - margin;
            }

            y -= height;
            DrawSingleStamp(gfx, new XRect(x, y, width, height), certificate, options, signTime);
            y -= gap;
        }
    }

    private static List<string> StampLines(X509Certificate2 certificate, StampOptions options)
    {
        var lines = new List<string>
        {
            $"Сертификат: {certificate.SerialNumber}",
            $"Владелец: {CertificateProvider.GetSubjectName(certificate)}",
            $"Действителен: с {certificate.NotBefore:dd.MM.yyyy} по {certificate.NotAfter:dd.MM.yyyy}",
        };
        if (!string.IsNullOrWhiteSpace(options.PoaNumber))
            lines.Add($"Действует на основании МЧД № {options.PoaNumber}");
        return lines;
    }

    private const double StampPad = 8;
    private const double StampLineHeight = 10.5;
    private const double StampTitleHeight = 24;

    private static double ComputeStampHeight(X509Certificate2 certificate, StampOptions options)
    {
        var logoSize = options.LogoPath is not null ? 34.0 : 0.0;
        var bodyLines = StampLines(certificate, options).Count + (options.WithDate ? 1 : 0);
        return StampPad * 2 + Math.Max(StampTitleHeight, logoSize) + 4 + bodyLines * StampLineHeight;
    }

    private static void DrawSingleStamp(
        XGraphics gfx, XRect rect, X509Certificate2 certificate, StampOptions options, DateTime signTime)
    {
        var width = rect.Width;
        var blue = XColor.FromArgb(0x1B, 0x4F, 0x9C);
        var pen = new XPen(blue, 1.2);
        var titleFont = new XFont("stamp", 8, XFontStyleEx.Bold);
        var textFont = new XFont("stamp", 7, XFontStyleEx.Regular);

        var lines = StampLines(certificate, options);
        var dateLine = options.WithDate ? $"Дата подписания: {signTime:dd.MM.yyyy HH:mm}" : null;
        var logoPath = options.LogoPath;

        const double pad = StampPad;
        const double lineHeight = StampLineHeight;
        const double titleHeight = StampTitleHeight;
        var logoSize = logoPath is not null ? 34.0 : 0.0;

        var x = rect.X;
        var y = rect.Y;

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
