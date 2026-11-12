using System;
using System.IO;
using System.Linq;

// Tier 2 of the proof ladder: finds the package's LICENSE.md among the
// runfiles and prints its status line.
public static class Consumer
{
    public static int Main()
    {
        var root = Environment.GetEnvironmentVariable("RUNFILES_DIR") ?? AppContext.BaseDirectory;
        var license = Directory
            .EnumerateFiles(root, "LICENSE.md", SearchOption.AllDirectories)
            .FirstOrDefault(path => path.Replace('\\', '/').Contains("sp.victim"));
        if (license == null)
        {
            Console.Error.WriteLine("socket-fixture SP.Victim: LICENSE.md not found under " + root);
            return 1;
        }
        var status = File.ReadLines(license).FirstOrDefault(line => line.StartsWith("STATUS:"));
        Console.WriteLine("socket-fixture SP.Victim: " + status);
        return 0;
    }
}
