using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Validation;
using DocumentFormat.OpenXml.Wordprocessing;
using SignService.Services;
using SignService.ViewModels;
using DW = DocumentFormat.OpenXml.Drawing.Wordprocessing;

// Штамп в документе Word: копия «имя (со штампом).docx» проходит проверку схемы
// OpenXML, исходник не меняется; «последняя»/«указанные» — плашки в конце текста,
// «первая» — колонтитул первой страницы (другие разделы не затронуты), «все» —
// все видимые нижние колонтитулы; подписание оригинала и копии со штампом.
// SIGNSERVICE_TEST_OUTPUT=<каталог> — сохранить полученные документы для просмотра.
internal static class WordStampTests
{
    private const string Title = "ДОКУМЕНТ ПОДПИСАН";

    public static async Task RunAsync(string tempRoot, DocumentSigner signer)
    {
        var root = Path.Combine(tempRoot, "word-stamp");
        Directory.CreateDirectory(root);
        using var certA = MakeCert("CN=\"Иванов Иван Иванович <директор> & Ко\", O=ООО Ромашка");
        using var certB = MakeCert("CN=Петрова Анна Сергеевна");
        using var certC = MakeCert("CN=Сидоров Пётр");
        var logo = WriteLogo(root);

        CheckEndOfText(root, certA, certB, certC, logo);
        CheckMacroEnabled(root, certA);
        CheckFirstPage(root, certA, logo);
        CheckFirstPageWithTitlePage(root, certA);
        CheckAllFooters(root, certA, certB, logo);
        CheckFormats(root, certA);
        await CheckSigning(root, signer, certA, certB, logo);
        await CheckSignCopyInViewModel(root, certA);
        await CheckBrokenDocument(root, signer, certA);
        Console.WriteLine("word stamp: end of text, first page, all footers, signing, schema validation: OK");
    }

    // Конец текста: документ заканчивается таблицей, у «Обычного» стиля красная
    // строка и выравнивание по ширине; три подписанта — по две плашки в строке.
    private static void CheckEndOfText(string root, X509Certificate2 certA, X509Certificate2 certB,
        X509Certificate2 certC, string logo)
    {
        var path = Path.Combine(root, "договор.docx");
        CreateDocument(path, (main, body) =>
        {
            body.Append(Para("Договор поставки"), Para("Текст договора."), DocumentTable());
            body.Append(Section(main, footer: AddFooter(main, "Страница ", pageField: true)));
        });
        var original = File.ReadAllBytes(path);

        var output = WordStamper.CreateStampedCopy(path, new[] { certA, certB, certC },
            new PdfStamper.StampOptions { LogoPath = logo, PoaNumber = "МЧД-42" }, new DateTime(2026, 10, 19, 14, 5, 0));
        Assert(output == Path.Combine(root, "договор (со штампом).docx"), "copy name: " + output);
        Assert(File.ReadAllBytes(path).SequenceEqual(original), "the original must not change");
        Validate(output);
        Keep(output);

        using (var doc = WordprocessingDocument.Open(output, false))
        {
            var main = doc.MainDocumentPart!;
            var body = main.Document!.Body!;
            var blocks = body.ChildElements.ToList();
            var layout = blocks.OfType<Table>().Last();
            var index = blocks.IndexOf(layout);
            Assert(blocks[index - 1] is Paragraph && blocks[index - 2] is Table,
                "a paragraph must separate the stamp from the document's own table");
            Assert(blocks[index + 1] is Paragraph && blocks[index + 2] is SectionProperties,
                "the stamp goes right before the final section properties");
            Assert(Count(layout, Title) == 3, "one stamp per signer");
            var text = layout.InnerText;
            foreach (var expected in new[]
                     {
                         "Иванов Иван Иванович <директор> & Ко", "Петрова Анна Сергеевна", "Сидоров Пётр",
                         "Сертификат: " + certA.SerialNumber, "Действует на основании МЧД № МЧД-42",
                         "Дата подписания: 19.10.2026 14:05",
                     })
                Assert(text.Contains(expected), "stamp text missing: " + expected);

            var rows = layout.Elements<TableRow>().ToList();
            Assert(rows.Count == 2 && rows.All(r => r.TableRowProperties?.GetFirstChild<CantSplit>() is not null),
                "two rows of two stamps on A4, rows are not split across pages");
            Assert(!rows[1].Elements<TableCell>().First().Descendants<Table>().Any()
                && rows[1].Elements<TableCell>().Last().Descendants<Table>().Any(),
                "the incomplete last row is pressed to the right edge");
            Assert(layout.Descendants<Drawing>().Count() == 3 && main.ImageParts.Count() == 1,
                "the logo is stored once and shown on each stamp");
            Assert(main.FooterParts.All(f => Count(f.Footer!, Title) == 0), "«last page» mode leaves footers alone");
            var normalIndent = layout.Descendants<Paragraph>().All(p => p.ParagraphProperties?.Indentation?.FirstLine?.Value == "0");
            Assert(normalIndent, "stamp paragraphs override the first-line indent of the Normal style");
        }

        // повторный штамп пересоздаёт копию из оригинала, а не дописывает к старой
        var again = WordStamper.CreateStampedCopy(path, new[] { certA }, new PdfStamper.StampOptions(), DateTime.Now);
        using (var doc = WordprocessingDocument.Open(again, false))
            Assert(Count(doc.MainDocumentPart!.Document!.Body!, Title) == 1, "re-stamping must start from the original");
        Validate(again);
    }

    private static void CheckMacroEnabled(string root, X509Certificate2 cert)
    {
        var path = Path.Combine(root, "шаблон.docm");
        CreateDocument(path, (main, body) => body.Append(Para("С макросами"), Section(main)), macro: true);
        var output = WordStamper.CreateStampedCopy(path, new[] { cert }, new PdfStamper.StampOptions(), DateTime.Now);
        Assert(output.EndsWith("шаблон (со штампом).docm", StringComparison.Ordinal), "docm keeps its extension: " + output);
        using (var doc = WordprocessingDocument.Open(output, false))
            Assert(doc.DocumentType == WordprocessingDocumentType.MacroEnabledDocument, "docm stays macro-enabled");
        Validate(output);
    }

    // «Первая страница»: у первого раздела не было особого колонтитула первой
    // страницы — он включается, шапка (с картинкой) и подвал копируются, плашка
    // добавляется только туда. Второй раздел с особой первой страницей прежде
    // показывал на ней пустые колонтитулы — так и остаётся.
    private static void CheckFirstPage(string root, X509Certificate2 cert, string logo)
    {
        var path = Path.Combine(root, "два раздела.docx");
        CreateDocument(path, (main, body) =>
        {
            var header = AddHeader(main, "Шапка бланка", File.ReadAllBytes(logo));
            var footer = AddFooter(main, "Подвал бланка");
            body.Append(Para("Раздел 1"), new Paragraph(new ParagraphProperties(Section(main, header, footer))));
            body.Append(Para("Раздел 2"), Section(main, titlePage: true));
        });

        var output = WordStamper.CreateStampedCopy(path, new[] { cert },
            new PdfStamper.StampOptions { Pages = PdfStamper.StampPages.First, LogoPath = logo }, DateTime.Now);
        Validate(output);
        Keep(output);

        using var doc = WordprocessingDocument.Open(output, false);
        var main = doc.MainDocumentPart!;
        var sections = main.Document!.Body!.Descendants<SectionProperties>().ToList();
        Assert(sections[0].GetFirstChild<TitlePage>() is not null, "first section gets a distinct first page");

        var firstFooter = (FooterPart)main.GetPartById(Ref<FooterReference>(sections[0], HeaderFooterValues.First)!);
        Assert(Count(firstFooter.Footer!, Title) == 1 && firstFooter.Footer!.InnerText.Contains("Подвал бланка"),
            "first page footer = old footer + stamp");
        var defaultFooter = (FooterPart)main.GetPartById(Ref<FooterReference>(sections[0], HeaderFooterValues.Default)!);
        Assert(Count(defaultFooter.Footer!, Title) == 0, "other pages keep the old footer");

        var firstHeader = (HeaderPart)main.GetPartById(Ref<HeaderReference>(sections[0], HeaderFooterValues.First)!);
        Assert(firstHeader.Header!.InnerText.Contains("Шапка бланка"), "first page keeps its header");
        var blip = firstHeader.Header!.Descendants<DocumentFormat.OpenXml.Drawing.Blip>().Single().Embed!.Value!;
        Assert(firstHeader.GetPartById(blip) is ImagePart, "the copied header keeps its picture");

        var second = Ref<FooterReference>(sections[1], HeaderFooterValues.First);
        Assert(second is not null && Count(((FooterPart)main.GetPartById(second)).Footer!, Title) == 0
            && Ref<HeaderReference>(sections[1], HeaderFooterValues.First) is not null,
            "the second section's first page must not inherit the stamp");

        var ids = DrawingIds(main);
        Assert(ids.Count == ids.Distinct().Count(), "drawing ids stay unique: " + string.Join(",", ids));
    }

    // Особая первая страница уже была: её подвал общий со вторым разделом —
    // плашка ставится в копию, второй раздел закрепляет прежний подвал.
    private static void CheckFirstPageWithTitlePage(string root, X509Certificate2 cert)
    {
        var path = Path.Combine(root, "титул.docx");
        CreateDocument(path, (main, body) =>
        {
            var titleFooter = AddFooter(main, "Подвал титула");
            body.Append(Para("Раздел 1"),
                new Paragraph(new ParagraphProperties(Section(main, firstFooter: titleFooter, titlePage: true))));
            body.Append(Para("Раздел 2"), Section(main, titlePage: true));
        });

        var output = WordStamper.CreateStampedCopy(path, new[] { cert },
            new PdfStamper.StampOptions { Pages = PdfStamper.StampPages.First }, DateTime.Now);
        Validate(output);

        using var doc = WordprocessingDocument.Open(output, false);
        var main = doc.MainDocumentPart!;
        var sections = main.Document!.Body!.Descendants<SectionProperties>().ToList();
        var first = (FooterPart)main.GetPartById(Ref<FooterReference>(sections[0], HeaderFooterValues.First)!);
        var second = (FooterPart)main.GetPartById(Ref<FooterReference>(sections[1], HeaderFooterValues.First)!);
        Assert(Count(first.Footer!, Title) == 1 && first.Footer!.InnerText.Contains("Подвал титула"),
            "stamp goes into a copy of the title footer");
        Assert(Count(second.Footer!, Title) == 0 && second.Footer!.InnerText.Contains("Подвал титула"),
            "the second section keeps the old title footer");
        Assert(sections[0].Elements<TitlePage>().Count() == 1, "no duplicate titlePg");
    }

    // «Все страницы»: обычный, первой страницы и чётных — в каждом видимом подвале
    // по плашке на подписанта; недостающие подвалы создаются.
    private static void CheckAllFooters(string root, X509Certificate2 certA, X509Certificate2 certB, string logo)
    {
        var path = Path.Combine(root, "все страницы.docx");
        CreateDocument(path, (main, body) =>
        {
            var settings = main.AddNewPart<DocumentSettingsPart>();
            settings.Settings = new Settings(new EvenAndOddHeaders());
            var f1 = AddFooter(main, "Подвал раздела 1");
            var f2 = AddFooter(main, "Подвал раздела 2");
            body.Append(DocumentTable(),
                new Paragraph(new ParagraphProperties(Section(main, footer: f1, titlePage: true))));
            body.Append(Para("Раздел 2"), Section(main, footer: f2, landscape: true));
        });

        var output = WordStamper.CreateStampedCopy(path, new[] { certA, certB },
            new PdfStamper.StampOptions { Pages = PdfStamper.StampPages.All, LogoPath = logo }, DateTime.Now);
        Validate(output);
        Keep(output);

        using var doc = WordprocessingDocument.Open(output, false);
        var main = doc.MainDocumentPart!;
        var sections = main.Document!.Body!.Descendants<SectionProperties>().ToList();
        string Shown(int section, HeaderFooterValues type)
        {
            for (var i = section; i >= 0; i--)
                if (Ref<FooterReference>(sections[i], type) is { } id)
                    return id;
            throw new Exception($"word stamp: no {((IEnumValue)type).Value} footer for section {section + 1}");
        }

        var shown = new[]
        {
            Shown(0, HeaderFooterValues.Default), Shown(0, HeaderFooterValues.First), Shown(0, HeaderFooterValues.Even),
            Shown(1, HeaderFooterValues.Default), Shown(1, HeaderFooterValues.Even),
        };
        foreach (var id in shown)
        {
            var footer = ((FooterPart)main.GetPartById(id)).Footer!;
            Assert(Count(footer, Title) == 2, $"footer {id} must carry both stamps once: {Count(footer, Title)}");
            Assert(footer.Descendants<Drawing>().Count() == 2, "logo on each stamp in the footer");
        }

        Assert(((FooterPart)main.GetPartById(Shown(0, HeaderFooterValues.Default))).Footer!.InnerText.Contains("Подвал раздела 1")
            && ((FooterPart)main.GetPartById(Shown(1, HeaderFooterValues.Default))).Footer!.InnerText.Contains("Подвал раздела 2"),
            "existing footer content stays");
        var ids = DrawingIds(main);
        Assert(ids.Count == ids.Distinct().Count(), "drawing ids stay unique");
    }

    private static void CheckFormats(string root, X509Certificate2 cert)
    {
        Assert(DocumentStamper.IsSupported("а.DOCX") && DocumentStamper.IsSupported("б.docm")
            && DocumentStamper.IsSupported("в.pdf") && !DocumentStamper.IsSupported("г.doc"),
            "supported formats: pdf, docx, docm");
        Assert(DocumentStamper.Note("г.doc", new PdfStamper.StampOptions())!.Contains(".docx"), "old .doc: save as .docx");
        Assert(DocumentStamper.Note("д.xlsx", new PdfStamper.StampOptions())!.Contains("PDF"), "other formats: no stamp");
        Assert(DocumentStamper.Note("е.pdf", new PdfStamper.StampOptions { Pages = PdfStamper.StampPages.Custom }) is null,
            "PDF honours page numbers");

        var custom = new PdfStamper.StampOptions { Pages = PdfStamper.StampPages.Custom, CustomPages = "2" };
        Assert(DocumentStamper.Note("ж.docx", custom)!.Contains("в конце текста"), "Word explains custom pages");
        var path = Path.Combine(root, "страницы.docx");
        CreateDocument(path, (main, body) => body.Append(Para("Текст")));
        var output = DocumentStamper.CreateStampedCopy(path, new[] { cert }, custom, DateTime.Now);
        using (var doc = WordprocessingDocument.Open(output, false))
            Assert(Count(doc.MainDocumentPart!.Document!.Body!, Title) == 1, "custom pages → end of text");
        Validate(output);

        // текст в две колонки: плашка по ширине колонки, а не страницы
        var columns = Path.Combine(root, "колонки.docx");
        CreateDocument(columns, (main, body) =>
        {
            var section = Section(main);
            section.InsertAfter(new Columns { ColumnCount = 2, Space = "708" }, section.GetFirstChild<PageMargin>()!);
            body.Append(Para("Левая колонка"), section);
        });
        var columnsOutput = WordStamper.CreateStampedCopy(columns, new[] { cert, cert }, new PdfStamper.StampOptions(), DateTime.Now);
        Validate(columnsOutput);
        using (var doc = WordprocessingDocument.Open(columnsOutput, false))
        {
            var layout = doc.MainDocumentPart!.Document!.Body!.Elements<Table>().Single();
            var width = int.Parse(layout.GetFirstChild<TableProperties>()!.GetFirstChild<TableWidth>()!.Width!.Value!);
            Assert(width <= (9355 - 708) / 2 && layout.Elements<TableRow>().Count() == 2,
                $"stamps fit one text column, one per row: width {width}");
        }
    }

    // Подписание с галочкой «Штамп»: по умолчанию подписывается оригинал, копия —
    // без подписи со всеми подписантами; в режиме «подписывать копию» подпись
    // относится к штампованному файлу.
    private static async Task CheckSigning(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, string logo)
    {
        var dir = Path.Combine(root, "signing");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "акт.docx");
        CreateDocument(path, (main, body) => body.Append(Para("Акт выполненных работ"), Section(main)));
        var original = await File.ReadAllBytesAsync(path);

        var first = await signer.SignFileAsync(path, certA, new DocumentSigner.SignOptions
        {
            Detached = true, Stamp = true, StampLogoPath = logo,
        });
        Assert(first.SignedDocumentPath == path && first.SignaturePath == path + ".sig", "the original is signed");
        Assert(first.StampedCopyPath == Path.Combine(dir, "акт (со штампом).docx") && File.Exists(first.StampedCopyPath),
            "unsigned stamped Word copy is created");
        Assert(!File.Exists(first.StampedCopyPath + ".sig"), "the separate copy is not signed");

        var second = await signer.SignFileAsync(path, certB, new DocumentSigner.SignOptions
        {
            Detached = true, MergeWithExisting = true, Stamp = true, StampLogoPath = logo,
        });
        Assert(second.SignerCount == 2 && (await File.ReadAllBytesAsync(path)).SequenceEqual(original),
            "co-signing keeps the original intact");
        var cms = new SignedCms(new ContentInfo(original), detached: true);
        cms.Decode(await File.ReadAllBytesAsync(second.SignaturePath));
        cms.CheckSignature(verifySignatureOnly: true);
        using (var doc = WordprocessingDocument.Open(second.StampedCopyPath!, false))
        {
            var body = doc.MainDocumentPart!.Document!.Body!;
            Assert(Count(body, Title) == 2 && body.InnerText.Contains("Иванов") && body.InnerText.Contains("Петрова"),
                "the copy lists every signer of the final .sig");
        }

        Validate(second.StampedCopyPath!);

        var copy = await signer.SignFileAsync(path, certA, new DocumentSigner.SignOptions
        {
            Detached = true, Stamp = true, StampSignCopy = true,
        });
        Assert(copy.SignedDocumentPath == first.StampedCopyPath && copy.SignaturePath == first.StampedCopyPath + ".sig",
            "sign-copy mode signs the stamped Word copy");
        var signedCopy = new SignedCms(new ContentInfo(await File.ReadAllBytesAsync(copy.SignedDocumentPath)), detached: true);
        signedCopy.Decode(await File.ReadAllBytesAsync(copy.SignaturePath));
        signedCopy.CheckSignature(verifySignatureOnly: true);
        Assert(CmsMerger.CountSigners(await File.ReadAllBytesAsync(path + ".sig")) == 2,
            "signing the copy leaves the original's signature alone");

        // подписанная копия больше не пересоздаётся — ни при подписании, ни инструментом «Штамп»
        var signedSig = await File.ReadAllBytesAsync(path + ".sig");
        var signedCopyBytes = await File.ReadAllBytesAsync(copy.SignedDocumentPath);
        foreach (var signCopy in new[] { false, true })
        {
            try
            {
                await signer.SignFileAsync(path, certB, new DocumentSigner.SignOptions
                {
                    Detached = true, MergeWithExisting = true, Stamp = true, StampSignCopy = signCopy,
                });
                throw new Exception("word stamp: a signed stamped copy must not be overwritten");
            }
            catch (InvalidOperationException e) when (e.Message.Contains("уже подписана"))
            {
            }
        }

        try
        {
            DocumentStamper.CreateStampedCopy(path, new[] { certB }, new PdfStamper.StampOptions(), DateTime.Now);
            throw new Exception("word stamp: the stamp tool must not overwrite a signed copy");
        }
        catch (InvalidOperationException e) when (e.Message.Contains("уже подписана"))
        {
        }

        Assert((await File.ReadAllBytesAsync(path + ".sig")).SequenceEqual(signedSig)
            && (await File.ReadAllBytesAsync(copy.SignedDocumentPath)).SequenceEqual(signedCopyBytes),
            "refused signing writes nothing: the original's .sig and the signed copy stay as they were");
    }

    private static async Task CheckSignCopyInViewModel(string root, X509Certificate2 cert)
    {
        var dir = Path.Combine(root, "vm");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "письмо.docx");
        CreateDocument(path, (main, body) => body.Append(Para("Письмо")));
        var settings = new AppSettings(Path.Combine(dir, "settings")) { CheckUpdatesOnStart = false };
        var vm = new MainWindowViewModel(new CertificateProvider(), new DocumentSigner(), settings,
            new CertificateVault(Path.Combine(dir, "vault")));
        vm.UseStamp = true;
        vm.StampSignCopy = true;
        vm.RequestStampOptionsAsync = _ => Task.FromResult<SignService.Views.StampOptionsDialog.Result?>(
            new SignService.Views.StampOptionsDialog.Result(vm.BuildInitialStampOptions(), SignCopy: true));
        await vm.AddFilesAsync(path);
        var item = vm.Files.Single();
        Assert(item.SignsStampedCopy && item.StatusDisplay.Contains("копия со штампом"),
            "Word in sign-copy mode signs the stamped copy: " + item.StatusDisplay);
        vm.SelectedCertificate = new CertificateItem(cert);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Signed && item.SignaturePath == Path.Combine(dir, "письмо (со штампом).docx.sig"),
            "stamped Word copy signed from the main window: " + item.StatusDisplay + " " + item.Message);
    }

    private static async Task CheckBrokenDocument(string root, DocumentSigner signer, X509Certificate2 cert)
    {
        var dir = Path.Combine(root, "broken");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "битый.docx");
        await File.WriteAllBytesAsync(path, new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 1, 2, 3 }); // как зашифрованный docx
        try
        {
            await signer.SignFileAsync(path, cert, new DocumentSigner.SignOptions { Detached = true, Stamp = true, StampSignCopy = true });
            throw new Exception("word stamp: a broken document must not be signed in sign-copy mode");
        }
        catch (InvalidOperationException e) when (e.Message.Contains("документ Word"))
        {
        }

        Assert(Directory.GetFiles(dir).Length == 1, "nothing is written for a broken document: "
            + string.Join(", ", Directory.GetFiles(dir).Select(Path.GetFileName)));
    }

    // ===== Построение тестовых документов =====

    private static void CreateDocument(string path, Action<MainDocumentPart, Body> fill, bool macro = false)
    {
        using var doc = WordprocessingDocument.Create(path,
            macro ? WordprocessingDocumentType.MacroEnabledDocument : WordprocessingDocumentType.Document);
        var main = doc.AddMainDocumentPart();
        main.Document = new Document(new Body());
        // «Обычный» как в типовом бланке: красная строка, по ширине, полуторный интервал.
        main.AddNewPart<StyleDefinitionsPart>().Styles = new Styles(
            new Style(
                new StyleName { Val = "Normal" },
                new StyleParagraphProperties(
                    new SpacingBetweenLines { After = "200", Line = "360", LineRule = LineSpacingRuleValues.Auto },
                    new Indentation { FirstLine = "709" },
                    new Justification { Val = JustificationValues.Both }),
                new StyleRunProperties(new FontSize { Val = "28" }))
            { Type = StyleValues.Paragraph, StyleId = "Normal", Default = true });
        fill(main, main.Document.Body!);
    }

    private static Paragraph Para(string text) => new(new Run(new Text(text)));

    private static Table DocumentTable() => new(
        new TableProperties(new TableWidth { Width = "5000", Type = TableWidthUnitValues.Pct }),
        new TableGrid(new GridColumn { Width = "4677" }, new GridColumn { Width = "4678" }),
        new TableRow(new TableCell(Para("Поставщик")), new TableCell(Para("Покупатель"))));

    private static SectionProperties Section(MainDocumentPart main, string? header = null, string? footer = null,
        string? firstFooter = null, bool titlePage = false, bool landscape = false)
    {
        var section = new SectionProperties();
        if (header is not null)
            section.Append(new HeaderReference { Type = HeaderFooterValues.Default, Id = header });
        if (footer is not null)
            section.Append(new FooterReference { Type = HeaderFooterValues.Default, Id = footer });
        if (firstFooter is not null)
            section.Append(new FooterReference { Type = HeaderFooterValues.First, Id = firstFooter });
        section.Append(
            landscape
                ? new PageSize { Width = 16838, Height = 11906, Orient = PageOrientationValues.Landscape }
                : new PageSize { Width = 11906, Height = 16838 },
            new PageMargin { Top = 1134, Right = 850, Bottom = 1134, Left = 1701, Header = 708, Footer = 708, Gutter = 0 });
        if (titlePage)
            section.Append(new TitlePage());
        return section;
    }

    private static string AddFooter(MainDocumentPart main, string text, bool pageField = false)
    {
        var part = main.AddNewPart<FooterPart>();
        var paragraph = new Paragraph(new ParagraphProperties(new Justification { Val = JustificationValues.Center }),
            new Run(new Text(text) { Space = SpaceProcessingModeValues.Preserve }));
        if (pageField)
            paragraph.Append(new SimpleField(new Run(new Text("1"))) { Instruction = " PAGE " });
        part.Footer = new Footer(paragraph);
        return main.GetIdOfPart(part);
    }

    private static string AddHeader(MainDocumentPart main, string text, byte[] png)
    {
        var part = main.AddNewPart<HeaderPart>();
        var image = part.AddImagePart(ImagePartType.Png);
        using (var stream = new MemoryStream(png))
            image.FeedData(stream);
        const long size = 360000;
        var drawing = new Drawing(new DW.Inline(
            new DW.Extent { Cx = size, Cy = size },
            new DW.DocProperties { Id = 1U, Name = "Герб" },
            new DocumentFormat.OpenXml.Drawing.Graphic(new DocumentFormat.OpenXml.Drawing.GraphicData(
                new DocumentFormat.OpenXml.Drawing.Pictures.Picture(
                    new DocumentFormat.OpenXml.Drawing.Pictures.NonVisualPictureProperties(
                        new DocumentFormat.OpenXml.Drawing.Pictures.NonVisualDrawingProperties { Id = 0U, Name = "Герб" },
                        new DocumentFormat.OpenXml.Drawing.Pictures.NonVisualPictureDrawingProperties()),
                    new DocumentFormat.OpenXml.Drawing.Pictures.BlipFill(
                        new DocumentFormat.OpenXml.Drawing.Blip { Embed = part.GetIdOfPart(image) },
                        new DocumentFormat.OpenXml.Drawing.Stretch(new DocumentFormat.OpenXml.Drawing.FillRectangle())),
                    new DocumentFormat.OpenXml.Drawing.Pictures.ShapeProperties(
                        new DocumentFormat.OpenXml.Drawing.Transform2D(
                            new DocumentFormat.OpenXml.Drawing.Offset { X = 0, Y = 0 },
                            new DocumentFormat.OpenXml.Drawing.Extents { Cx = size, Cy = size }),
                        new DocumentFormat.OpenXml.Drawing.PresetGeometry { Preset = DocumentFormat.OpenXml.Drawing.ShapeTypeValues.Rectangle })))
            { Uri = "http://schemas.openxmlformats.org/drawingml/2006/picture" })));
        part.Header = new Header(new Paragraph(new Run(drawing), new Run(new Text(" " + text) { Space = SpaceProcessingModeValues.Preserve })));
        return main.GetIdOfPart(part);
    }

    private static string WriteLogo(string dir)
    {
        var path = Path.Combine(dir, "логотип.png");
        using var surface = SkiaSharp.SKSurface.Create(new SkiaSharp.SKImageInfo(640, 320));
        surface.Canvas.Clear(SkiaSharp.SKColors.Transparent);
        using var paint = new SkiaSharp.SKPaint { Color = new SkiaSharp.SKColor(0x1B, 0x4F, 0x9C), IsAntialias = true };
        surface.Canvas.DrawRoundRect(new SkiaSharp.SKRect(10, 10, 630, 310), 60, 60, paint);
        using var snapshot = surface.Snapshot();
        using var png = snapshot.Encode(SkiaSharp.SKEncodedImageFormat.Png, 100);
        File.WriteAllBytes(path, png.ToArray());
        return path;
    }

    // ===== Проверки =====

    private static void Validate(string path)
    {
        using var doc = WordprocessingDocument.Open(path, false);
        var errors = new OpenXmlValidator(FileFormatVersions.Office2019).Validate(doc).ToList();
        Assert(errors.Count == 0, $"«{Path.GetFileName(path)}» fails OpenXML validation:\n" + string.Join("\n",
            errors.Take(10).Select(e => $"  {e.Part?.Uri} {e.Path?.XPath}: {e.Description}")));
    }

    private static string? Ref<T>(SectionProperties section, HeaderFooterValues type) where T : HeaderFooterReferenceType =>
        section.Elements<T>().FirstOrDefault(r => r.Type?.Value == type)?.Id?.Value;

    private static int Count(OpenXmlElement root, string text) =>
        root.Descendants<Text>().Count(t => t.Text == text);

    private static List<uint> DrawingIds(MainDocumentPart main) =>
        new OpenXmlElement[] { main.Document! }
            .Concat(main.HeaderParts.Select(h => (OpenXmlElement)h.Header!))
            .Concat(main.FooterParts.Select(f => (OpenXmlElement)f.Footer!))
            .SelectMany(r => r.Descendants<DW.DocProperties>())
            .Select(d => d.Id!.Value)
            .ToList();

    private static void Keep(string path)
    {
        if (Environment.GetEnvironmentVariable("SIGNSERVICE_TEST_OUTPUT") is { Length: > 0 } dir)
        {
            Directory.CreateDirectory(dir);
            File.Copy(path, Path.Combine(dir, Path.GetFileName(path)), overwrite: true);
        }
    }

    private static X509Certificate2 MakeCert(string subject)
    {
        using var key = RSA.Create(2048);
        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new Exception("word stamp: " + message);
    }
}
