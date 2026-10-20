using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SignService.Services;

/// <summary>
/// Визуальный штамп на копии документа по его формату: PDF — <see cref="PdfStamper"/>,
/// Word (.docx, .docm) — <see cref="WordStamper"/>. Остальные форматы подписываются без штампа.
/// </summary>
public static class DocumentStamper
{
    public static bool IsSupported(string filePath) =>
        PdfStamper.IsPdf(filePath) || WordStamper.IsWord(filePath);

    /// <summary>«имя (со штампом).pdf» или «имя (со штампом).docx» рядом с документом.</summary>
    public static string StampedCopyPath(string filePath) =>
        WordStamper.IsWord(filePath) ? WordStamper.StampedCopyPath(filePath) : PdfStamper.StampedCopyPath(filePath);

    /// <summary>
    /// Отказ, если у копии со штампом есть своя подпись («… (со штампом).pdf.sig»):
    /// новая копия — другой файл, и та подпись перестала бы ему соответствовать.
    /// </summary>
    public static void ThrowIfCopySigned(string filePath)
    {
        var copy = StampedCopyPath(filePath);
        if (!File.Exists(copy + ".sig"))
            return;
        var name = Path.GetFileName(copy);
        throw new InvalidOperationException(
            $"Копия «{name}» уже подписана («{name}.sig»), новая копия со штампом сделала бы эту подпись " +
            $"недействительной. Чтобы добавить подпись к копии, подпишите сам файл «{name}» без штампа; " +
            "чтобы сделать копию заново, удалите или переименуйте её файл подписи.");
    }

    /// <summary>
    /// Создаёт «имя (со штампом).pdf» или «имя (со штампом).docx» рядом с документом.
    /// Подписанная копия не перезаписывается (см. <see cref="ThrowIfCopySigned"/>).
    /// </summary>
    public static string CreateStampedCopy(
        string filePath,
        IReadOnlyList<X509Certificate2> certificates,
        PdfStamper.StampOptions options,
        DateTime signTime)
    {
        ThrowIfCopySigned(filePath);
        if (WordStamper.IsWord(filePath))
            return WordStamper.CreateStampedCopy(filePath, certificates, options, signTime);
        if (PdfStamper.IsPdf(filePath))
            return PdfStamper.CreateStampedCopy(filePath, certificates, options, signTime);
        throw new InvalidOperationException(UnsupportedMessage(filePath));
    }

    /// <summary>
    /// Пояснение для лога: почему штампа нет или почему он стоит не на выбранных
    /// страницах (Word). null — штамп поставлен так, как выбрано.
    /// </summary>
    public static string? Note(string filePath, PdfStamper.StampOptions options) =>
        WordStamper.IsWord(filePath) ? WordStamper.PlacementNote(options)
        : PdfStamper.IsPdf(filePath) ? null
        : UnsupportedMessage(filePath);

    /// <summary>Как назвать формат в сообщении об ошибке штампа.</summary>
    public static string FormatName(string filePath) =>
        WordStamper.IsWord(filePath) ? "документ Word" : "PDF";

    private static string UnsupportedMessage(string filePath)
    {
        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        return extension is ".doc" or ".rtf" or ".odt"
            ? $"штамп не ставится: формат {extension} не поддерживается — сохраните документ как .docx"
            : "штамп не ставится: поддерживаются PDF и документы Word (.docx, .docm)";
    }
}
