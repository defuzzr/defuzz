"""Known structured data formats; parsing is not execution or safety approval."""
import json
import re

_JSONC_COMMENTS = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/')
_JSONC_TRAILING_COMMA = re.compile(r'"(?:\\.|[^"\\])*"|,\s*(?=[}\]])')
_FIXTURE_FILES = frozenset({'cross_checks_sample.json', 'executable_inventory_sample.json', 'profile_memory_scenarios.json'})


def classification(path):
    if path.suffix == '.code-workspace' or path.name.startswith('tsconfig') and path.suffix == '.json':
        return 'jsonc_config'
    if path.name in {'biome.json', 'biome.jsonc'}:
        return 'jsonc_data'
    if path.name in {'pnpm-lock.yaml', 'pnpm-workspace.yaml', 'package-lock.json', 'provenance.json'}:
        return 'data'
    if ('tests' in path.parts and 'fixtures' in path.parts and
            (path.name.startswith(('options_', 'python_options_')) or path.name in _FIXTURE_FILES)):
        return 'fixture_data'
    if '.github' in path.parts and 'workflows' in path.parts:
        return 'workflow'
    return None


# Accepted PyYAML range; must match plugin.yaml. Safety rests on the behaviour
# probe below, which runs once per loaded module on whatever version is installed.
YAML_ACCEPTED = '>=6.0.3,<7'
_YAML_FLOOR, _YAML_CEILING = (6, 0, 3), (7,)
_yaml_probed = set()


def _version_tuple(text):
    parts = str(text).split('.')
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _yaml_probe(yaml):
    """Return the first audit-relied-on behaviour the installed PyYAML lacks, or None."""
    for doc in ("!!python/object/apply:os.getcwd []", "a: !custom 1"):
        try:
            yaml.safe_load(doc)
            return 'tags rejected'
        except yaml.YAMLError:
            pass
    seen = []

    class Probe(yaml.SafeLoader):
        def flatten_mapping(self, node):  # facts.UniqueKeyLoader relies on this hook
            seen.append(id(node))
            super().flatten_mapping(node)

    # Probe is a SafeLoader subclass (no object construction) reading a fixed literal.
    value = yaml.load("b: &b {k: 1}\nx: {<<: *b, k: 2}\ny: [{d: 1}]\n", Loader=Probe)
    if len(set(seen)) != 4:
        return 'mapping hook called for every mapping'
    if value != {'b': {'k': 1}, 'x': {'k': 2}, 'y': [{'d': 1}]}:
        return 'merge keys'
    shared = yaml.safe_load("a: &x [1]\nb: *x\n")
    if shared['a'] is not shared['b']:
        return 'aliases shared, not copied'
    if yaml.safe_load("a: y\nb: on\nc: 0o7\n") != {'a': 'y', 'b': True, 'c': '0o7'}:
        return 'YAML 1.1 scalar resolution'
    return None


def check_audit_yaml(yaml):
    """Raise ValueError (one plain line) unless `yaml` is an accepted, behaving PyYAML."""
    found = getattr(yaml, '__version__', None)
    version = _version_tuple(found) if found is not None else None
    if version is None or not _YAML_FLOOR <= version < _YAML_CEILING:
        raise ValueError(f'Audit requires PyYAML {YAML_ACCEPTED}; found {found or "unknown"}')
    key = (id(yaml), found)
    if key in _yaml_probed:
        return
    try:
        failed = _yaml_probe(yaml)
    except Exception as exc:  # a changed internal is a failed check, not a crash
        failed = f'probe raised {type(exc).__name__}'
    if failed:
        raise ValueError(f'Audit requires PyYAML {YAML_ACCEPTED}; found {found}, which fails the check: {failed}')
    _yaml_probed.add(key)


def _load_yaml(text):
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(f'Audit requires PyYAML {YAML_ACCEPTED}; found none') from exc
    check_audit_yaml(yaml)
    try:
        return list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise ValueError('invalid structured data') from exc


def parse_data(path, data, *, unbounded=False):
    text = data.decode('utf-8')
    kind = classification(path)
    if path.suffix in {'.json', '.jsonc', '.code-workspace'}:
        if kind and kind.startswith('jsonc'):
            text = _JSONC_COMMENTS.sub(lambda m: m[0] if m[0].startswith('"') else ' ', text)
            text = _JSONC_TRAILING_COMMA.sub(lambda m: m[0] if m[0].startswith('"') else '', text)
        documents = [json.loads(text)]
    else:
        documents = _load_yaml(text)
    remaining = 10000

    def check(value, ancestors=()):
        nonlocal remaining
        remaining -= 1
        if not unbounded and (remaining < 0 or len(ancestors) > 64):
            raise ValueError('structured data budget exceeded')
        if isinstance(value, (list, dict)):
            if id(value) in ancestors:
                raise ValueError('recursive structured data')
            for child in value.values() if isinstance(value, dict) else value:
                check(child, ancestors + (id(value),))

    for document in documents:
        check(document)
    return documents
