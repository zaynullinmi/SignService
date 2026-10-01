using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SignService.Services;

internal static class AtomicFile
{
    public static async Task WriteAsync(string path, byte[] bytes, bool overwrite = true,
        CancellationToken cancellationToken = default)
    {
        var fullPath = Path.GetFullPath(path);
        var temporary = Path.Combine(Path.GetDirectoryName(fullPath)!, ".signservice-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                8192, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporary, fullPath, overwrite);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public static void Write(string path, byte[] bytes, bool overwrite = false) =>
        WriteAsync(path, bytes, overwrite).GetAwaiter().GetResult();
}
