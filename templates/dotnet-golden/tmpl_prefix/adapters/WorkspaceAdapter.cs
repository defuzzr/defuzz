using TmplPrefix.Domain;
using TmplPrefix.Foundation;

namespace TmplPrefix.Adapters;

public static class WorkspaceAdapter
{
    public static string ResolveWorkspaceName()
    {
        var name = WorkspaceDomain.GetWorkspaceName();
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new WorkspaceException("Workspace name must not be empty.");
        }

        return name;
    }
}
