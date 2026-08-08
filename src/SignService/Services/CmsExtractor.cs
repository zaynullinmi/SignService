using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SignService.Services;

/// <summary>
/// Извлечение содержимого криптоконтейнера (.sig/.p7s) в файлы рядом с ним:
/// вложенный документ прикреплённой подписи, откреплённая подпись со всеми
/// подписантами и отдельные подписи по каждому подписанту.
/// Существующие файлы не перезаписываются — при совпадении имён добавляется номер.
/// </summary>
public static class CmsExtractor
{
    public sealed record ExtractionResult(
        string ContainerName,
        bool WasAttached,
        int SignerCount,
        string? DocumentPath,
        string? DetachedPath,
        IReadOnlyList<string> SignerFiles);

    public static ExtractionResult ExtractToFiles(string containerPath)
    {
        var raw = File.ReadAllBytes(containerPath);
        var info = CmsMerger.Inspect(raw);
        var directory = Path.GetDirectoryName(containerPath) ?? ".";

        // «отчет.pdf.sig» → базовое имя «отчет.pdf»; контейнер без известного
        // расширения подписи получает суффикс, чтобы не смешивать имена.
        var fileName = Path.GetFileName(containerPath);
        var baseName = fileName.EndsWith(".sig", StringComparison.OrdinalIgnoreCase)
                    || fileName.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase)
                    || fileName.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase)
            ? fileName[..^4]
            : fileName + ".извлечено";

        string? documentPath = null;
        string? detachedPath = null;

        if (info.HasContent)
        {
            var content = CmsMerger.ExtractContent(raw)
                ?? throw new InvalidOperationException("Не удалось извлечь документ из контейнера.");
            documentPath = UniquePath(directory, baseName, containerPath);
            File.WriteAllBytes(documentPath, content);

            // Откреплённый вариант подписи к извлечённому документу.
            detachedPath = UniquePath(
                directory, Path.GetFileName(documentPath) + " (откреплённая).sig", containerPath);
            File.WriteAllBytes(detachedPath, CmsMerger.ConvertToDetached(raw));
        }

        var signerFiles = new List<string>();
        if (info.SignerNames.Count > 1)
        {
            foreach (var (signerName, signature) in CmsMerger.SplitBySigner(raw))
            {
                var path = UniquePath(directory, $"{baseName} ({Sanitize(signerName)}).sig", containerPath);
                File.WriteAllBytes(path, signature);
                signerFiles.Add(path);
            }
        }

        return new ExtractionResult(
            fileName, info.HasContent, info.SignerNames.Count, documentPath, detachedPath, signerFiles);
    }

    // Свободный путь в каталоге: не перезаписываем ни существующие файлы, ни сам контейнер.
    private static string UniquePath(string directory, string desiredName, string containerPath)
    {
        var stem = Path.GetFileNameWithoutExtension(desiredName);
        var extension = Path.GetExtension(desiredName);
        for (var i = 0; ; i++)
        {
            var name = i == 0 ? desiredName : $"{stem} ({i}){extension}";
            var path = Path.Combine(directory, name);
            if (!File.Exists(path)
                && !string.Equals(Path.GetFullPath(path), Path.GetFullPath(containerPath), StringComparison.OrdinalIgnoreCase))
                return path;
        }
    }

    private static string Sanitize(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(name.Select(c => invalid.Contains(c) ? '_' : c).ToArray()).Trim();
        return cleaned.Length == 0 ? "подписант" : cleaned;
    }
}
