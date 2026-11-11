using System.Diagnostics;
using System.Xml.Linq;

namespace Xtask;

internal enum Layer
{
    Foundation = 0,
    Domain = 1,
    Adapters = 2,
    Apps = 3,
}

internal sealed record ProjectSpec(
    string Name,
    string MemberDir,
    IReadOnlyList<string> Dependencies
);

public static class Program
{
    internal const string FoundationPkg =
        // Package name after scaffold substitution.
        "tmpl-prefix-foundation";

    internal const string DomainPkg =
        // Package name after scaffold substitution.
        "tmpl-prefix-domain";

    internal const string AdaptersPkg =
        // Package name after scaffold substitution.
        "tmpl-prefix-adapters";

    internal const string CliPkg =
        // Package name after scaffold substitution.
        "tmpl-prefix-cli";

    public static int Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        try
        {
            var root = FindWorkspaceRoot();
            var cmd = ParseCommand(args);
            switch (cmd)
            {
                case "ci":
                    RunDotnet(root, "restore", "--locked-mode", "--nologo");
                    RunDotnet(root, "format", "--verify-no-changes", "--no-restore");
                    RunDotnet(root, "build", "--no-restore", "--nologo", "-warnaserror");
                    RunDotnet(root, "test", "--no-build", "--nologo");
                    RunLayerCheck(root);
                    return 0;
                case "fmt":
                    RunDotnet(root, "format", "--no-restore");
                    return 0;
                case "layers":
                    RunLayerCheck(root);
                    return 0;
                case "self-test":
                    RunSelfTests(root);
                    return 0;
                default:
                    throw new InvalidOperationException($"Unsupported command: {cmd}");
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    internal static string ParseCommand(IReadOnlyList<string> args)
    {
        if (args.Count == 0)
        {
            throw new InvalidOperationException(
                "missing xtask subcommand (expected: ci, fmt, layers, or self-test)"
            );
        }

        if (args.Count > 1)
        {
            throw new InvalidOperationException($"unexpected extra argument `{args[1]}`");
        }

        var sub = args[0];
        if (sub is "ci" or "fmt" or "layers" or "self-test")
        {
            return sub;
        }

        throw new InvalidOperationException(
            $"unknown xtask subcommand `{sub}` (expected: ci, fmt, layers, or self-test)"
        );
    }

    internal static Layer? ParseLayer(string memberDir)
    {
        var first = memberDir
            .Trim('/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault();
        return first switch
        {
            "foundation" => Layer.Foundation,
            "domain" => Layer.Domain,
            "adapters" => Layer.Adapters,
            "apps" => Layer.Apps,
            _ => null,
        };
    }

    internal static IReadOnlyList<string> CheckLayerRules(IReadOnlyList<ProjectSpec> specs)
    {
        var errors = new List<string>();
        var projectLayers = new Dictionary<string, Layer>(StringComparer.Ordinal);
        var xtaskProjects = new HashSet<string>(StringComparer.Ordinal) { "xtask" };

        foreach (var spec in specs)
        {
            if (spec.MemberDir == "xtask" || spec.Name == "xtask")
            {
                xtaskProjects.Add(spec.Name);
                continue;
            }

            var parsed = ParseLayer(spec.MemberDir);
            if (parsed is Layer layer)
            {
                projectLayers[spec.Name] = layer;
            }
            else
            {
                errors.Add(
                    $"project `{spec.Name}` in `{spec.MemberDir}` does not belong to a known layer directory"
                );
            }
        }

        foreach (var spec in specs)
        {
            if (!projectLayers.TryGetValue(spec.Name, out var layer))
            {
                continue;
            }

            foreach (var dep in spec.Dependencies)
            {
                if (xtaskProjects.Contains(dep))
                {
                    errors.Add(
                        $"layer violation: `{spec.Name}` ({layer}) cannot depend on `{dep}` (xtask)"
                    );
                }
                else if (projectLayers.TryGetValue(dep, out var depLayer) && depLayer >= layer)
                {
                    errors.Add(
                        $"layer violation: `{spec.Name}` ({layer}) cannot depend on `{dep}` ({depLayer})"
                    );
                }
            }
        }

        return errors;
    }

    private static void RunLayerCheck(string root)
    {
        var specs = LoadWorkspaceSpecs(root);
        var errors = CheckLayerRules(specs);
        if (errors.Count > 0)
        {
            throw new InvalidOperationException(string.Join(Environment.NewLine, errors));
        }

        Console.WriteLine($"layer check passed ({specs.Count} workspace projects verified)");
    }

    internal static IReadOnlyList<ProjectSpec> LoadWorkspaceSpecs(string root)
    {
        var csprojPaths = new List<string>();
        DiscoverCsprojFiles(root, csprojPaths);
        csprojPaths.Sort(StringComparer.Ordinal);
        var pathToName = new Dictionary<string, string>(StringComparer.Ordinal);
        var rawRefs =
            new List<(string CsprojPath, string Name, string MemberDir, List<string> RefPaths)>();

        foreach (var csproj in csprojPaths)
        {
            var fullPath = Path.GetFullPath(csproj);
            var doc = XDocument.Load(fullPath);
            var pkgId = doc.Descendants("PackageId")
                .Select(x => x.Value.Trim())
                .FirstOrDefault(v => !string.IsNullOrEmpty(v));
            var name = pkgId ?? Path.GetFileNameWithoutExtension(fullPath);
            pathToName[fullPath] = name;

            var projDir =
                Path.GetDirectoryName(fullPath)
                ?? throw new InvalidOperationException($"invalid project path `{fullPath}`");
            var relDir = Path.GetRelativePath(root, projDir).Replace('\\', '/');
            var refs = doc.Descendants("ProjectReference")
                .Select(el => el.Attribute("Include")?.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => Path.GetFullPath(Path.Combine(projDir, v!.Replace('\\', '/'))))
                .ToList();
            rawRefs.Add((fullPath, name, relDir, refs));
        }

        var specs = new List<ProjectSpec>(rawRefs.Count);
        foreach (var item in rawRefs)
        {
            var deps = item
                .RefPaths.Select(rp =>
                    pathToName.TryGetValue(rp, out var depName)
                        ? depName
                        : Path.GetFileNameWithoutExtension(rp)
                )
                .Distinct(StringComparer.Ordinal)
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToList();
            specs.Add(new ProjectSpec(item.Name, item.MemberDir, deps));
        }

        return specs;
    }

    private static void DiscoverCsprojFiles(string currentDir, List<string> csprojPaths)
    {
        foreach (
            var file in Directory.GetFiles(currentDir, "*.csproj", SearchOption.TopDirectoryOnly)
        )
        {
            csprojPaths.Add(file);
        }

        foreach (var subDir in Directory.GetDirectories(currentDir))
        {
            var name = Path.GetFileName(subDir);
            if (
                string.IsNullOrEmpty(name)
                || name.StartsWith('.')
                || string.Equals(name, "target", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "bin", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "obj", StringComparison.OrdinalIgnoreCase)
            )
            {
                continue;
            }

            DiscoverCsprojFiles(subDir, csprojPaths);
        }
    }

    private static string FindWorkspaceRoot()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            var dir = new DirectoryInfo(start);
            while (dir is not null)
            {
                var props = Path.Combine(dir.FullName, "Directory.Build.props");
                var xtaskProj = Path.Combine(dir.FullName, "xtask", "Xtask.csproj");
                if (File.Exists(props) && File.Exists(xtaskProj))
                {
                    return dir.FullName;
                }

                dir = dir.Parent;
            }
        }

        throw new InvalidOperationException("failed to locate workspace root");
    }

    private static void RunDotnet(string root, params string[] dotnetArgs)
    {
        var joined = string.Join(' ', dotnetArgs);
        Console.WriteLine($"+ dotnet {joined}");
        var psi = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = root,
            UseShellExecute = false,
        };
        foreach (var arg in dotnetArgs)
        {
            psi.ArgumentList.Add(arg);
        }

        // MSBuild runs Exec scripts from the temp folder without quoting the
        // path, so a temp path with a space breaks `dotnet test`. Use a
        // space-free folder under the ignored `target` folder instead.
        if (Path.GetTempPath().Any(char.IsWhiteSpace))
        {
            var tmp = Path.Combine(root, "target", "tmp");
            if (!tmp.Any(char.IsWhiteSpace))
            {
                Directory.CreateDirectory(tmp);
                psi.Environment["TMPDIR"] = tmp;
            }
        }

        using var proc =
            Process.Start(psi) ?? throw new InvalidOperationException("failed to start dotnet");
        proc.WaitForExit();
        if (proc.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"command `dotnet {joined}` exited with code {proc.ExitCode}"
            );
        }
    }

    private static void RunSelfTests(string root)
    {
        var valid = SampleWorkspace([], []);
        if (CheckLayerRules(valid).Count != 0)
        {
            throw new InvalidOperationException("valid workspace should pass layer rules");
        }

        var foundViolation = CheckLayerRules(SampleWorkspace([DomainPkg], []));
        if (
            foundViolation.Count != 1
            || !foundViolation[0].Contains(FoundationPkg, StringComparison.Ordinal)
        )
        {
            throw new InvalidOperationException("foundation -> domain violation not detected");
        }

        var domViolation = CheckLayerRules(SampleWorkspace([], [AdaptersPkg, CliPkg]));
        if (domViolation.Count != 2)
        {
            throw new InvalidOperationException("domain -> adapters/cli violations not detected");
        }

        var xtaskDepViolation = CheckLayerRules(SampleWorkspace(["xtask"], []));
        if (
            xtaskDepViolation.Count != 1
            || !xtaskDepViolation[0].Contains("xtask", StringComparison.Ordinal)
        )
        {
            throw new InvalidOperationException("foundation -> xtask violation not detected");
        }

        var rogueSpecs = SampleWorkspace([], []);
        rogueSpecs.Add(new ProjectSpec("rogue-pkg", "rogue", []));
        var rogueViolation = CheckLayerRules(rogueSpecs);
        if (
            rogueViolation.Count != 1
            || !rogueViolation[0]
                .Contains("does not belong to a known layer directory", StringComparison.Ordinal)
        )
        {
            throw new InvalidOperationException("unknown layer directory violation not detected");
        }

        var realSpecs = LoadWorkspaceSpecs(root);
        if (realSpecs.Count < 5 || CheckLayerRules(realSpecs).Count != 0)
        {
            throw new InvalidOperationException("real workspace manifest failed layer rules");
        }

        if (ParseCommand(["ci"]) != "ci" || ParseCommand(["layers"]) != "layers")
        {
            throw new InvalidOperationException("CLI command parsing failed");
        }

        Console.WriteLine("xtask self-tests passed (7 assertions)");
    }

    private static List<ProjectSpec> SampleWorkspace(
        IReadOnlyList<string> extraFoundation,
        IReadOnlyList<string> extraDomain
    )
    {
        var domainDeps = new List<string> { FoundationPkg };
        domainDeps.AddRange(extraDomain);
        return
        [
            new ProjectSpec(FoundationPkg, "foundation", extraFoundation),
            new ProjectSpec(DomainPkg, "domain", domainDeps),
            new ProjectSpec(AdaptersPkg, "adapters", [FoundationPkg, DomainPkg]),
            new ProjectSpec(CliPkg, "apps/cli", [FoundationPkg, DomainPkg, AdaptersPkg]),
        ];
    }
}
