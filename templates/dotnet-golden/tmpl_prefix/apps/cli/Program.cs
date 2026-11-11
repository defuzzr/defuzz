using TmplPrefix.Adapters;
using TmplPrefix.Domain;
using TmplPrefix.Foundation;

namespace TmplPrefix.Cli;

public static class Program
{
    public static int Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length == 1 && args[0] == "--self-test")
        {
            return RunSelfTests();
        }

        Console.WriteLine(WorkspaceAdapter.ResolveWorkspaceName());
        return 0;
    }

    private static int RunSelfTests()
    {
        var domainName = WorkspaceDomain.GetWorkspaceName();
        var adapterName = WorkspaceAdapter.ResolveWorkspaceName();
        if (domainName != WorkspaceException.WorkspaceName || adapterName != domainName)
        {
            throw new WorkspaceException("Layer wiring self-test failed.");
        }

        if (string.IsNullOrWhiteSpace(WorkspaceException.SnakePrefix))
        {
            throw new WorkspaceException("SnakePrefix must not be empty.");
        }

        if (WorkspaceDomain.GetEnvPrefix() != WorkspaceException.EnvPrefix)
        {
            throw new WorkspaceException("EnvPrefix mismatch.");
        }

        var err = new WorkspaceException("boom");
        if (err.Message != "boom")
        {
            throw new WorkspaceException("WorkspaceException message mismatch.");
        }

        Console.WriteLine("cli self-tests passed (4 assertions)");
        return 0;
    }
}
