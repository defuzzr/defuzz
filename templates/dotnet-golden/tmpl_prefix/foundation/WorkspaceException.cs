namespace TmplPrefix.Foundation;

public sealed class WorkspaceException : Exception
{
    public const string WorkspaceName =
        // Canonical kebab-case workspace slug after scaffold substitution.
        "tmpl-prefix";

    public const string SnakePrefix =
        // Canonical snake_case prefix after scaffold substitution.
        "tmpl_prefix";

    public const string EnvPrefix =
        // Canonical SCREAMING_SNAKE_CASE prefix after scaffold substitution.
        "TMPL_PREFIX";

    public WorkspaceException() { }

    public WorkspaceException(string message)
        : base(message) { }

    public WorkspaceException(string message, Exception innerException)
        : base(message, innerException) { }
}
