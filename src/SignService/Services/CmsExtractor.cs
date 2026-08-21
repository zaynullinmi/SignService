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

    /// <summary>Результат объединения файлов подписей без подписания.</summary>
    public sealed record MergeFilesResult(
        string OutputPath,
        int SignerCount,
        bool AttachedOutput,
        string DocumentNote,
        IReadOnlyList<string> ExcludedSigners,
        IReadOnlyList<string> UnverifiedSigners);

    /// <summary>
    /// Объединяет несколько файлов подписей (откреплённые .sig и/или прикреплённые
    /// криптоконтейнеры) в один файл со всеми подписантами — без создания своей подписи.
    /// Документ для проверки соответствия подписей берётся из прикреплённого контейнера,
    /// иначе — из файла рядом («документ.pdf.sig» → «документ.pdf»); если документа нет,
    /// объединение выполняется без проверки. Если среди входов есть прикреплённый
    /// контейнер, результат тоже прикреплённый (документ сохраняется внутри).
    /// </summary>
    public static MergeFilesResult MergeSignatureFiles(IReadOnlyList<string> paths)
    {
        if (paths.Count < 2)
            throw new ArgumentException("Выберите не менее двух файлов подписей для объединения.");

        var inputs = paths.Select(File.ReadAllBytes).ToList();

        // Документ: из прикреплённого контейнера либо из файла рядом с .sig.
        byte[]? document = null;
        string documentNote = "";
        foreach (var input in inputs)
        {
            var content = CmsMerger.ExtractContent(input);
            if (content is not null)
            {
                document = content;
                documentNote = "документ взят из прикреплённого контейнера";
                break;
            }
        }

        if (document is null)
        {
            foreach (var path in paths)
            {
                if (!path.EndsWith(".sig", StringComparison.OrdinalIgnoreCase))
                    continue;
                var documentPath = path[..^4];
                if (File.Exists(documentPath))
                {
                    document = File.ReadAllBytes(documentPath);
                    documentNote = $"проверено по документу «{Path.GetFileName(documentPath)}»";
                    break;
                }
            }
        }

        byte[] merged;
        IReadOnlyList<string> excluded = Array.Empty<string>();
        IReadOnlyList<string> unverified = Array.Empty<string>();
        if (document is not null)
        {
            var result = CmsMerger.MergeForDocument(inputs, document);
            merged = result.Signature;
            excluded = result.ExcludedSigners;
            unverified = result.UnverifiedSigners;
        }
        else
        {
            merged = CmsMerger.Merge(inputs);
            documentNote = "документ не найден — соответствие подписей не проверялось";
        }

        var info = CmsMerger.Inspect(merged);

        var directory = Path.GetDirectoryName(paths[0]) ?? ".";
        var firstName = Path.GetFileName(paths[0]);
        var baseName = firstName.EndsWith(".sig", StringComparison.OrdinalIgnoreCase)
                    || firstName.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase)
                    || firstName.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase)
            ? firstName[..^4]
            : firstName;

        var outputPath = UniquePath(directory, $"{baseName} (объединённая).sig", paths);
        File.WriteAllBytes(outputPath, merged);

        return new MergeFilesResult(
            outputPath, info.SignerNames.Count, info.HasContent, documentNote, excluded, unverified);
    }

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
            documentPath = UniquePath(directory, baseName, new[] { containerPath });
            File.WriteAllBytes(documentPath, content);

            // Откреплённый вариант подписи к извлечённому документу.
            detachedPath = UniquePath(
                directory, Path.GetFileName(documentPath) + " (откреплённая).sig", new[] { containerPath });
            File.WriteAllBytes(detachedPath, CmsMerger.ConvertToDetached(raw));
        }

        var signerFiles = new List<string>();
        if (info.SignerNames.Count > 1)
        {
            foreach (var (signerName, signature) in CmsMerger.SplitBySigner(raw))
            {
                var path = UniquePath(directory, $"{baseName} ({Sanitize(signerName)}).sig", new[] { containerPath });
                File.WriteAllBytes(path, signature);
                signerFiles.Add(path);
            }
        }

        return new ExtractionResult(
            fileName, info.HasContent, info.SignerNames.Count, documentPath, detachedPath, signerFiles);
    }

    // Свободный путь в каталоге: не перезаписываем ни существующие файлы, ни входные.
    private static string UniquePath(string directory, string desiredName, IReadOnlyList<string> avoidPaths)
    {
        var stem = Path.GetFileNameWithoutExtension(desiredName);
        var extension = Path.GetExtension(desiredName);
        for (var i = 0; ; i++)
        {
            var name = i == 0 ? desiredName : $"{stem} ({i}){extension}";
            var path = Path.Combine(directory, name);
            if (!File.Exists(path)
                && !avoidPaths.Any(a => string.Equals(
                    Path.GetFullPath(path), Path.GetFullPath(a), StringComparison.OrdinalIgnoreCase)))
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
