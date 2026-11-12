using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

// Tier 2 of the proof ladder: finds the package's assembly among the
// runfiles and prints the ASCII marker its first bytes hold.
public static class Consumer
{
    // The runfiles tree: the one the environment names, else every
    // `<name>.runfiles` directory beside the directory this assembly runs
    // from (rules_csharp puts the program in `<name>_/`).
    private static IEnumerable<string> RunfilesRoots()
    {
        var named = Environment.GetEnvironmentVariable("RUNFILES_DIR");
        if (!string.IsNullOrEmpty(named))
        {
            return new[] { named };
        }
        var here = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        var parent = Path.GetDirectoryName(here);
        return parent == null
            ? Enumerable.Empty<string>()
            : Directory.EnumerateDirectories(parent, "*.runfiles");
    }

    public static int Main()
    {
        var assembly = RunfilesRoots()
            .SelectMany(root => Directory.EnumerateFiles(root, "SP.Victim.dll", SearchOption.AllDirectories))
            .FirstOrDefault();
        if (assembly == null)
        {
            Console.Error.WriteLine("socket-fixture SP.Victim: SP.Victim.dll is not among the runfiles");
            return 1;
        }
        var head = File.ReadAllBytes(assembly).TakeWhile(b => b >= 0x20 && b < 0x7f).ToArray();
        Console.WriteLine("socket-fixture SP.Victim: " + Encoding.ASCII.GetString(head));
        return 0;
    }
}
