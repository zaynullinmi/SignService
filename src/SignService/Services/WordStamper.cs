using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using SkiaSharp;
using A = DocumentFormat.OpenXml.Drawing;
using DW = DocumentFormat.OpenXml.Drawing.Wordprocessing;
using PIC = DocumentFormat.OpenXml.Drawing.Pictures;

namespace SignService.Services;

/// <summary>
/// Визуальный штамп в документе Word (.docx, .docm): те же плашки, что на PDF
/// («Документ подписан электронной подписью», сертификат, владелец, срок, МЧД,
/// дата, логотип), — таблицами в рамке, по плашке на подписанта, у правого края.
/// Страниц в файле Word нет (их считает программа просмотра), поэтому:
/// «последняя» и «указанные» — плашки в конце текста, «первая» — в нижнем
/// колонтитуле первой страницы, «все» — в нижних колонтитулах всех страниц.
/// Исходный файл не меняется: создаётся копия «имя (со штампом).docx».
/// </summary>
public static class WordStamper
{
    private const string Blue = "1B4F9C";
    private const string FontName = "Arial";
    private const string TitleSize = "16"; // 8 pt, в полупунктах
    private const string TextSize = "14";  // 7 pt
    private const uint BorderSize = 10;    // 1,25 pt, в восьмых долях пункта

    // Размеры — в twips (1/20 пункта).
    private const int MinStampWidth = 3969; // 7 см
    private const int MaxStampWidth = 5000; // ≈ 8,8 см — как плашка на PDF (250 pt)
    private const int StampGap = 113;       // 2 мм между плашками
    private const int CellPadding = 113;
    private const int LogoTwips = 680;      // 34 pt — как на PDF
    private const long EmuPerTwip = 635;
    private const int MaxLogoPixels = 400;

    private const string Word2010Namespace = "http://schemas.microsoft.com/office/word/2010/wordml";

    public static bool IsWord(string filePath) =>
        Path.GetExtension(filePath).ToLowerInvariant() is ".docx" or ".docm";

    /// <summary>«имя (со штампом).docx» рядом с документом (расширение сохраняется).</summary>
    public static string StampedCopyPath(string filePath) =>
        Path.Combine(Path.GetDirectoryName(filePath) ?? ".",
            $"{Path.GetFileNameWithoutExtension(filePath)} (со штампом){Path.GetExtension(filePath)}");

    /// <summary>Пояснение, если выбранные страницы в Word отработаны иначе, чем на PDF.</summary>
    public static string? PlacementNote(PdfStamper.StampOptions options) =>
        options.Pages == PdfStamper.StampPages.Custom
            ? "в Word страницы не выбираются по номерам — штамп поставлен в конце текста"
            : null;

    /// <summary>
    /// Создаёт копию «имя (со штампом).docx» (существующая заменяется) с плашками
    /// всех переданных подписантов. Копия пишется атомарно; исходник только читается.
    /// </summary>
    public static string CreateStampedCopy(
        string docPath,
        IReadOnlyList<X509Certificate2> certificates,
        PdfStamper.StampOptions options,
        DateTime signTime)
        => CreateStampedCopy(docPath, PdfStamper.ToSigners(certificates, options, signTime), options);

    /// <summary>Копия со штампом: по плашке на подписанта, со своими датой и МЧД.</summary>
    public static string CreateStampedCopy(
        string docPath, IReadOnlyList<PdfStamper.StampSigner> signers, PdfStamper.StampOptions options)
    {
        if (signers.Count == 0)
            throw new ArgumentException("Нет подписантов для штампа.", nameof(signers));

        var outputPath = StampedCopyPath(docPath);
        using var buffer = new MemoryStream();
        using (var source = new FileStream(docPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            source.CopyTo(buffer);

        using (var document = WordprocessingDocument.Open(buffer, true))
        {
            var stamp = new Stamp(document, signers, options);
            switch (options.Pages)
            {
                case PdfStamper.StampPages.First:
                    stamp.IntoFirstPageFooter();
                    break;
                case PdfStamper.StampPages.All:
                    stamp.IntoAllFooters();
                    break;
                default:
                    stamp.IntoEndOfText();
                    break;
            }
        }

        AtomicFile.Write(outputPath, buffer.ToArray(), overwrite: true);
        return outputPath;
    }

    private sealed record Logo(byte[] Png, int Width, int Height);

    /// <summary>Штамп для одного документа: разметка плашек и правка колонтитулов.</summary>
    private sealed class Stamp
    {
        private readonly MainDocumentPart _main;
        private readonly Body _body;
        private readonly IReadOnlyList<PdfStamper.StampSigner> _signers;
        private readonly PdfStamper.StampOptions _options;
        private readonly Logo? _logo;
        private readonly Dictionary<OpenXmlPart, string> _logoIds = new();
        private uint _nextDrawingId;

        public Stamp(WordprocessingDocument document, IReadOnlyList<PdfStamper.StampSigner> signers,
            PdfStamper.StampOptions options)
        {
            _main = document.MainDocumentPart
                ?? throw new InvalidOperationException("В файле нет основной части документа Word.");
            _body = _main.Document?.Body
                ?? throw new InvalidOperationException("В документе Word нет текста.");
            _signers = signers;
            _options = options;
            _logo = LoadLogo(options.LogoPath);
            _nextDrawingId = MaxDrawingId() + 1;
        }

        /// <summary>«Последняя» и «указанные»: плашки после последнего абзаца.</summary>
        public void IntoEndOfText()
        {
            var sections = _body.Descendants<SectionProperties>().ToList();
            var last = sections.LastOrDefault(s => s.Parent == _body);
            var width = TextWidth(last ?? sections.LastOrDefault(), withColumns: true);
            foreach (var element in Block(_main, width, spaceBefore: 240))
            {
                if (last is null)
                    _body.Append(element);
                else
                    _body.InsertBefore(element, last);
            }
        }

        /// <summary>
        /// «Все»: в каждый нижний колонтитул, который виден на страницах (обычный,
        /// первой страницы раздела, чётных), — при его отсутствии создаётся новый.
        /// </summary>
        public void IntoAllFooters()
        {
            var sections = Sections();
            var width = sections.Min(s => TextWidth(s, withColumns: false));
            var evenAndOdd = _main.DocumentSettingsPart?.Settings?.GetFirstChild<EvenAndOddHeaders>() is { } even
                && (even.Val is null || even.Val.Value);
            var stamped = new HashSet<string>();
            for (var i = 0; i < sections.Count; i++)
            {
                var types = new List<HeaderFooterValues> { HeaderFooterValues.Default };
                if (HasTitlePage(sections[i]))
                    types.Add(HeaderFooterValues.First);
                if (evenAndOdd)
                    types.Add(HeaderFooterValues.Even);

                foreach (var type in types)
                {
                    var id = Effective<FooterReference>(sections, i, type);
                    if (id is null)
                    {
                        id = NewFooter(null);
                        SetReference(sections[i], new FooterReference { Type = type, Id = id });
                    }

                    if (stamped.Add(id))
                        AppendToFooter((FooterPart)_main.GetPartById(id), width);
                }
            }
        }

        /// <summary>
        /// «Первая»: отдельный колонтитул первой страницы (копия прежнего + плашки).
        /// Если у раздела не было «особого колонтитула первой страницы», он
        /// включается, а верхний колонтитул копируется, чтобы первая страница
        /// выглядела как раньше. Колонтитулы других разделов не меняются.
        /// </summary>
        public void IntoFirstPageFooter()
        {
            var sections = Sections();
            var first = sections[0];
            var hadTitlePage = HasTitlePage(first);
            var laterTitlePage = sections.Skip(1).Any(HasTitlePage);
            var shownType = hadTitlePage ? HeaderFooterValues.First : HeaderFooterValues.Default;

            // Нижний: копия того, что было на первой странице, + плашки.
            var shownFooter = Effective<FooterReference>(sections, 0, shownType);
            var footerId = NewFooter(shownFooter);
            PinForLaterSections<FooterReference>(sections, laterTitlePage);
            SetReference(first, new FooterReference { Type = HeaderFooterValues.First, Id = footerId });
            AppendToFooter((FooterPart)_main.GetPartById(footerId), TextWidth(first, withColumns: false));

            if (hadTitlePage)
                return;

            // Верхний: первая страница показывала обычный — копируем его в «первую страницу».
            var defaultHeader = Effective<HeaderReference>(sections, 0, HeaderFooterValues.Default);
            var staleFirstHeader = Own<HeaderReference>(first, HeaderFooterValues.First);
            if (defaultHeader is not null || staleFirstHeader is not null)
            {
                var headerId = NewHeader(defaultHeader);
                PinForLaterSections<HeaderReference>(sections, laterTitlePage);
                SetReference(first, new HeaderReference { Type = HeaderFooterValues.First, Id = headerId });
            }

            SetTitlePage(first);
        }

        // Разделы без своей ссылки наследуют колонтитул предыдущего раздела. Перед
        // заменой колонтитула первой страницы в первом разделе второй раздел
        // закрепляет прежний — иначе плашка появилась бы и на его первой странице.
        private void PinForLaterSections<T>(List<SectionProperties> sections, bool laterTitlePage)
            where T : HeaderFooterReferenceType, new()
        {
            if (sections.Count < 2 || !laterTitlePage || Own<T>(sections[1], HeaderFooterValues.First) is not null)
                return;
            var previous = Own<T>(sections[0], HeaderFooterValues.First)
                ?? (typeof(T) == typeof(FooterReference) ? NewFooter(null) : NewHeader(null));
            SetReference(sections[1], new T { Type = HeaderFooterValues.First, Id = previous });
        }

        private List<SectionProperties> Sections()
        {
            var sections = _body.Descendants<SectionProperties>().ToList();
            if (sections.Count == 0 || sections[^1].Parent != _body)
            {
                var last = new SectionProperties();
                _body.Append(last);
                sections.Add(last);
            }

            return sections;
        }

        private static bool HasTitlePage(SectionProperties section) =>
            section.GetFirstChild<TitlePage>() is { } titlePage && (titlePage.Val is null || titlePage.Val.Value);

        private static void SetTitlePage(SectionProperties section)
        {
            section.RemoveAllChildren<TitlePage>();
            // По схеме titlePg стоит перед textDirection, bidi, rtlGutter, docGrid…
            var next = section.ChildElements.FirstOrDefault(e => e is TextDirection or BiDi or GutterOnRight
                or DocGrid or PrinterSettingsReference or SectionPropertiesChange);
            if (next is null)
                section.Append(new TitlePage());
            else
                section.InsertBefore(new TitlePage(), next);
        }

        private string? Own<T>(SectionProperties section, HeaderFooterValues type) where T : HeaderFooterReferenceType =>
            section.Elements<T>()
                .Where(r => (r.Type?.Value ?? HeaderFooterValues.Default) == type)
                .Select(r => r.Id?.Value)
                .FirstOrDefault(id => id is not null && IsPart<T>(id));

        private string? Effective<T>(List<SectionProperties> sections, int index, HeaderFooterValues type)
            where T : HeaderFooterReferenceType
        {
            for (var i = index; i >= 0; i--)
            {
                if (Own<T>(sections[i], type) is { } id)
                    return id;
            }

            return null;
        }

        private bool IsPart<T>(string id) where T : HeaderFooterReferenceType =>
            _main.TryGetPartById(id, out var part)
            && (typeof(T) == typeof(FooterReference) ? part is FooterPart : part is HeaderPart);

        private static void SetReference(SectionProperties section, HeaderFooterReferenceType reference)
        {
            var type = reference.Type?.Value ?? HeaderFooterValues.Default;
            foreach (var old in section.ChildElements.OfType<HeaderFooterReferenceType>()
                         .Where(r => r.GetType() == reference.GetType()
                             && (r.Type?.Value ?? HeaderFooterValues.Default) == type)
                         .ToList())
                old.Remove();

            // Ссылки на колонтитулы — первые элементы sectPr.
            var lastReference = section.ChildElements.OfType<HeaderFooterReferenceType>().LastOrDefault();
            if (lastReference is null)
                section.PrependChild(reference);
            else
                section.InsertAfter(reference, lastReference);
        }

        private string NewFooter(string? copyOf)
        {
            var part = _main.AddNewPart<FooterPart>();
            if (copyOf is null)
                part.Footer = new Footer();
            else
                CopyPart((FooterPart)_main.GetPartById(copyOf), part);
            return _main.GetIdOfPart(part);
        }

        private string NewHeader(string? copyOf)
        {
            var part = _main.AddNewPart<HeaderPart>();
            if (copyOf is null)
                part.Header = new Header(new Paragraph());
            else
                CopyPart((HeaderPart)_main.GetPartById(copyOf), part);
            return _main.GetIdOfPart(part);
        }

        // Копия колонтитула: содержимое и связи (картинки и прочие части — общие,
        // внешние ссылки — те же). Номера рисунков и абзацев в копии новые.
        private void CopyPart(OpenXmlPart source, OpenXmlPart target)
        {
            source.RootElement?.Save();
            using (var stream = source.GetStream(FileMode.Open, FileAccess.Read))
                target.FeedData(stream);
            foreach (var child in source.Parts)
                target.AddPart(child.OpenXmlPart, child.RelationshipId);
            foreach (var link in source.HyperlinkRelationships)
                target.AddHyperlinkRelationship(link.Uri, link.IsExternal, link.Id);
            foreach (var external in source.ExternalRelationships)
                target.AddExternalRelationship(external.RelationshipType, external.Uri, external.Id);

            var root = target.RootElement
                ?? throw new InvalidOperationException("Не удалось прочитать колонтитул документа.");
            foreach (var drawing in root.Descendants<DW.DocProperties>())
                drawing.Id = _nextDrawingId++;
            foreach (var element in root.Descendants().Where(e => e is Paragraph or TableRow).ToList())
            {
                element.RemoveAttribute("paraId", Word2010Namespace);
                element.RemoveAttribute("textId", Word2010Namespace);
            }

            foreach (var sdtId in root.Descendants<SdtId>().ToList())
                sdtId.Remove();
        }

        private void AppendToFooter(FooterPart part, int width)
        {
            var footer = part.Footer ??= new Footer();
            foreach (var element in Block(part, width, spaceBefore: 60))
                footer.Append(element);
        }

        private uint MaxDrawingId()
        {
            var roots = new List<OpenXmlPartRootElement?> { _main.Document };
            roots.AddRange(_main.HeaderParts.Select(p => (OpenXmlPartRootElement?)p.Header));
            roots.AddRange(_main.FooterParts.Select(p => (OpenXmlPartRootElement?)p.Footer));
            roots.Add(_main.FootnotesPart?.Footnotes);
            roots.Add(_main.EndnotesPart?.Endnotes);
            roots.Add(_main.WordprocessingCommentsPart?.Comments);
            return roots.Where(r => r is not null)
                .SelectMany(r => r!.Descendants<DW.DocProperties>())
                .Select(d => d.Id?.Value ?? 0)
                .DefaultIfEmpty(0u)
                .Max();
        }

        // Ширина текста раздела: страница без полей (и без переплёта); для колонок — колонка.
        private static int TextWidth(SectionProperties? section, bool withColumns)
        {
            var size = section?.GetFirstChild<PageSize>();
            var margin = section?.GetFirstChild<PageMargin>();
            var width = (int)(size?.Width?.Value ?? 11906)
                - (int)(margin?.Left?.Value ?? 1701)
                - (int)(margin?.Right?.Value ?? 850)
                - (int)(margin?.Gutter?.Value ?? 0);
            if (withColumns && section?.GetFirstChild<Columns>() is { } columns
                && columns.ColumnCount?.Value is > 1 and var count)
            {
                var widths = columns.Elements<Column>()
                    .Select(c => int.TryParse(c.Width?.Value, out var w) ? w : 0)
                    .Where(w => w > 0)
                    .ToList();
                var space = int.TryParse(columns.Space?.Value, out var s) ? s : 720;
                width = columns.EqualWidth?.Value == false && widths.Count > 0
                    ? widths.Min()
                    : (width - space * (count - 1)) / count;
            }

            return Math.Max(width, 1440);
        }

        /// <summary>
        /// Плашки у правого края: таблица-раскладка без рамок, в строке столько
        /// плашек, сколько входит по ширине; неполная строка прижата вправо.
        /// </summary>
        private IEnumerable<OpenXmlElement> Block(OpenXmlPart host, int available, int spaceBefore)
        {
            var columns = Math.Clamp((available + StampGap) / (MinStampWidth + StampGap), 1, _signers.Count);
            var stampWidth = Math.Min(MaxStampWidth, (available - StampGap * (columns - 1)) / columns);
            var totalWidth = stampWidth * columns + StampGap * (columns - 1);

            var grid = new TableGrid();
            for (var c = 0; c < columns; c++)
            {
                if (c > 0)
                    grid.Append(new GridColumn { Width = StampGap.ToString() });
                grid.Append(new GridColumn { Width = stampWidth.ToString() });
            }

            var layout = new Table(
                new TableProperties(
                    new TableWidth { Width = totalWidth.ToString(), Type = TableWidthUnitValues.Dxa },
                    new TableJustification { Val = TableRowAlignmentValues.Right },
                    Borders(BorderValues.None),
                    new TableLayout { Type = TableLayoutValues.Fixed },
                    // Зазор между строками плашек — нижним полем ячейки: абзац после
                    // вложенной таблицы программы просмотра могут не показывать.
                    new TableCellMarginDefault(
                        new TopMargin { Width = "0", Type = TableWidthUnitValues.Dxa },
                        new TableCellLeftMargin { Width = 0, Type = TableWidthValues.Dxa },
                        new BottomMargin { Width = StampGap.ToString(), Type = TableWidthUnitValues.Dxa },
                        new TableCellRightMargin { Width = 0, Type = TableWidthValues.Dxa })),
                grid);

            for (var start = 0; start < _signers.Count; start += columns)
            {
                var signers = _signers.Skip(start).Take(columns).ToList();
                var empty = columns - signers.Count;
                var row = new TableRow(new TableRowProperties(new CantSplit()));
                for (var c = 0; c < columns; c++)
                {
                    if (c > 0)
                        row.Append(Cell(StampGap, Spacer(0, 20)));
                    row.Append(c < empty
                        ? Cell(stampWidth, Spacer(0, 20))
                        : Cell(stampWidth, StampTable(signers[c - empty], stampWidth, host), Spacer(0, 20)));
                }

                layout.Append(row);
            }

            // Абзац до таблицы не даёт ей слиться с таблицей документа; после — обязателен.
            return new OpenXmlElement[] { Spacer(spaceBefore, 20, keepNext: true), layout, Spacer(0, 20) };
        }

        private Table StampTable(PdfStamper.StampSigner signer, int width, OpenXmlPart host)
        {
            var logoId = LogoRelationship(host);
            var logoColumn = LogoTwips + CellPadding * 2;
            var grid = logoId is null
                ? new TableGrid(new GridColumn { Width = width.ToString() })
                : new TableGrid(
                    new GridColumn { Width = logoColumn.ToString() },
                    new GridColumn { Width = (width - logoColumn).ToString() });

            var table = new Table(
                new TableProperties(
                    new TableWidth { Width = width.ToString(), Type = TableWidthUnitValues.Dxa },
                    Borders(BorderValues.Single),
                    new TableLayout { Type = TableLayoutValues.Fixed },
                    new TableCellMarginDefault(
                        new TopMargin { Width = "57", Type = TableWidthUnitValues.Dxa },
                        new TableCellLeftMargin { Width = CellPadding, Type = TableWidthValues.Dxa },
                        new BottomMargin { Width = "57", Type = TableWidthUnitValues.Dxa },
                        new TableCellRightMargin { Width = CellPadding, Type = TableWidthValues.Dxa })),
                grid);

            var title = new List<OpenXmlElement>
            {
                Text(PdfStamper.TitleLine1, bold: true, TitleSize),
                Text(PdfStamper.TitleLine2, bold: true, TitleSize),
            };
            var heading = new TableRow(new TableRowProperties(new CantSplit()));
            if (logoId is not null)
            {
                heading.Append(Cell(logoColumn, new Paragraph(Layout(0, null), new Run(LogoDrawing(logoId)))));
                heading.Append(Cell(width - logoColumn, title.ToArray()));
            }
            else
            {
                heading.Append(Cell(width, title.ToArray()));
            }

            var lines = PdfStamper.StampLines(signer, _options);
            var body = lines.Select((line, i) => (OpenXmlElement)Text(line, bold: false, TextSize, i == 0 ? 60 : 0))
                .ToArray();
            var details = new TableRow(new TableRowProperties(new CantSplit()),
                Cell(width, logoId is null ? 1 : 2, body));

            table.Append(heading, details);
            return table;
        }

        private static TableBorders Borders(BorderValues outer)
        {
            T Border<T>(BorderValues value) where T : BorderType, new() => value == BorderValues.Single
                ? new T { Val = value, Size = BorderSize, Space = 0, Color = Blue }
                : new T { Val = value, Size = 0, Space = 0, Color = "auto" };

            return new TableBorders(
                Border<TopBorder>(outer),
                Border<LeftBorder>(outer),
                Border<BottomBorder>(outer),
                Border<RightBorder>(outer),
                Border<InsideHorizontalBorder>(BorderValues.None),
                Border<InsideVerticalBorder>(BorderValues.None));
        }

        private static TableCell Cell(int width, params OpenXmlElement[] content) => Cell(width, 1, content);

        private static TableCell Cell(int width, int span, params OpenXmlElement[] content)
        {
            var properties = new TableCellProperties(new TableCellWidth { Width = width.ToString(), Type = TableWidthUnitValues.Dxa });
            if (span > 1)
                properties.Append(new GridSpan { Val = span });
            properties.Append(new TableCellVerticalAlignment { Val = TableVerticalAlignmentValues.Center });
            var cell = new TableCell(properties);
            cell.Append(content);
            return cell;
        }

        // Явные отступы и интервалы: стиль «Обычный» документа (красная строка,
        // полуторный интервал, выравнивание по ширине) не должен менять плашку.
        private static ParagraphProperties Layout(int spaceBefore, int? exactLine, bool keepNext = false)
        {
            var properties = new ParagraphProperties();
            if (keepNext)
                properties.Append(new KeepNext());
            properties.Append(
                new SpacingBetweenLines
                {
                    Before = spaceBefore.ToString(),
                    BeforeAutoSpacing = false,
                    After = "0",
                    AfterAutoSpacing = false,
                    Line = (exactLine ?? 240).ToString(),
                    LineRule = exactLine is null ? LineSpacingRuleValues.Auto : LineSpacingRuleValues.Exact,
                },
                new Indentation { Left = "0", Right = "0", FirstLine = "0" },
                new Justification { Val = JustificationValues.Left });
            return properties;
        }

        private static Paragraph Text(string text, bool bold, string size, int spaceBefore = 0)
        {
            var run = new RunProperties(new RunFonts { Ascii = FontName, HighAnsi = FontName, EastAsia = FontName, ComplexScript = FontName });
            if (bold)
                run.Append(new Bold(), new BoldComplexScript());
            run.Append(new NoProof(), new Color { Val = Blue }, new FontSize { Val = size }, new FontSizeComplexScript { Val = size });
            return new Paragraph(Layout(spaceBefore, null),
                new Run(run, new Text(text) { Space = SpaceProcessingModeValues.Preserve }));
        }

        // Пустой абзац заданной высоты (exact): отступ перед плашками и обязательный
        // абзац после таблицы (в документе и в ячейке после вложенной таблицы).
        private static Paragraph Spacer(int spaceBefore, int height, bool keepNext = false)
        {
            var properties = Layout(spaceBefore, height, keepNext);
            properties.Append(new ParagraphMarkRunProperties(new FontSize { Val = "2" }, new FontSizeComplexScript { Val = "2" }));
            return new Paragraph(properties);
        }

        private string? LogoRelationship(OpenXmlPart host)
        {
            if (_logo is null)
                return null;
            if (_logoIds.TryGetValue(host, out var id))
                return id;

            var image = host switch
            {
                MainDocumentPart main => main.AddImagePart(ImagePartType.Png),
                FooterPart footer => footer.AddImagePart(ImagePartType.Png),
                _ => throw new InvalidOperationException("Неожиданная часть документа для логотипа."),
            };
            using (var stream = new MemoryStream(_logo.Png))
                image.FeedData(stream);
            id = host.GetIdOfPart(image);
            _logoIds[host] = id;
            return id;
        }

        private Drawing LogoDrawing(string relationshipId)
        {
            var logo = _logo!;
            var scale = (double)LogoTwips * EmuPerTwip / Math.Max(logo.Width, logo.Height);
            var cx = (long)Math.Round(logo.Width * scale);
            var cy = (long)Math.Round(logo.Height * scale);
            var id = _nextDrawingId++;
            const string name = "Логотип";

            return new Drawing(new DW.Inline(
                new DW.Extent { Cx = cx, Cy = cy },
                new DW.EffectExtent { LeftEdge = 0L, TopEdge = 0L, RightEdge = 0L, BottomEdge = 0L },
                new DW.DocProperties { Id = id, Name = name },
                new DW.NonVisualGraphicFrameDrawingProperties(new A.GraphicFrameLocks { NoChangeAspect = true }),
                new A.Graphic(new A.GraphicData(
                    new PIC.Picture(
                        new PIC.NonVisualPictureProperties(
                            new PIC.NonVisualDrawingProperties { Id = 0U, Name = name },
                            new PIC.NonVisualPictureDrawingProperties()),
                        new PIC.BlipFill(new A.Blip { Embed = relationshipId }, new A.Stretch(new A.FillRectangle())),
                        new PIC.ShapeProperties(
                            new A.Transform2D(new A.Offset { X = 0L, Y = 0L }, new A.Extents { Cx = cx, Cy = cy }),
                            new A.PresetGeometry(new A.AdjustValueList()) { Preset = A.ShapeTypeValues.Rectangle })))
                { Uri = "http://schemas.openxmlformats.org/drawingml/2006/picture" }))
            {
                DistanceFromTop = 0U,
                DistanceFromBottom = 0U,
                DistanceFromLeft = 0U,
                DistanceFromRight = 0U,
            });
        }

        // Логотип — в PNG (прозрачность сохраняется), крупные картинки уменьшаются:
        // на плашке он 34 pt. Не читается — штамп без логотипа, как на PDF.
        private static Logo? LoadLogo(string? path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return null;
            try
            {
                using var file = File.OpenRead(path);
                using var decoded = SKBitmap.Decode(file);
                if (decoded is null || decoded.Width <= 0 || decoded.Height <= 0)
                    return null;

                var scale = Math.Min(1.0, (double)MaxLogoPixels / Math.Max(decoded.Width, decoded.Height));
                using var resized = scale < 1
                    ? decoded.Resize(new SKImageInfo(
                            Math.Max(1, (int)Math.Round(decoded.Width * scale)),
                            Math.Max(1, (int)Math.Round(decoded.Height * scale)),
                            SKColorType.Rgba8888, SKAlphaType.Premul),
                        SKFilterQuality.High)
                    : null;
                var bitmap = resized ?? decoded;
                using var image = SKImage.FromBitmap(bitmap);
                using var png = image.Encode(SKEncodedImageFormat.Png, 100);
                return png is null ? null : new Logo(png.ToArray(), bitmap.Width, bitmap.Height);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
