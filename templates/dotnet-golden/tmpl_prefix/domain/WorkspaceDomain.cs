using TmplPrefix.Foundation;

namespace TmplPrefix.Domain;

public static class WorkspaceDomain
{
    public static string GetWorkspaceName() => WorkspaceException.WorkspaceName;

    public static string GetEnvPrefix() => WorkspaceException.EnvPrefix;
}
