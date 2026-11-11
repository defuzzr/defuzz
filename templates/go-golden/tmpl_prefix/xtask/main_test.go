package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testModule = "tmpl-prefix"

func sampleWorkspace(extraFoundation, extraDomain []string) []packageSpec {
	domainImports := append([]string{testModule + "/foundation"}, extraDomain...)
	return []packageSpec{
		{
			importPath: testModule + "/foundation",
			relDir:     "foundation",
			imports:    extraFoundation,
		},
		{
			importPath: testModule + "/domain",
			relDir:     "domain",
			imports:    domainImports,
		},
		{
			importPath: testModule + "/adapters",
			relDir:     "adapters",
			imports:    []string{testModule + "/foundation", testModule + "/domain"},
		},
		{
			importPath: testModule + "/apps/cli",
			relDir:     "apps/cli",
			imports:    []string{testModule + "/foundation", testModule + "/domain", testModule + "/adapters"},
		},
	}
}

func TestValidLayeredWorkspacePasses(t *testing.T) {
	violations := checkLayerRules(testModule, sampleWorkspace(nil, nil))
	if len(violations) != 0 {
		t.Fatalf("expected no layer violations, got: %v", violations)
	}
}

func TestFoundationDependingOnDomainFails(t *testing.T) {
	violations := checkLayerRules(testModule, sampleWorkspace([]string{testModule + "/domain"}, nil))
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got: %v", violations)
	}
	if !strings.Contains(violations[0], "foundation") || !strings.Contains(violations[0], "domain") {
		t.Fatalf("unexpected violation message: %s", violations[0])
	}
}

func TestDomainDependingOnAdaptersOrAppsFails(t *testing.T) {
	violations := checkLayerRules(
		testModule,
		sampleWorkspace(nil, []string{testModule + "/adapters", testModule + "/apps/cli"}),
	)
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got: %v", violations)
	}
}

func TestUnknownLayerDirectoryFails(t *testing.T) {
	specs := append(sampleWorkspace(nil, nil), packageSpec{
		importPath: testModule + "/rogue",
		relDir:     "rogue",
		imports:    nil,
	})
	violations := checkLayerRules(testModule, specs)
	if len(violations) != 1 || !strings.Contains(violations[0], "known layer directory") {
		t.Fatalf("expected unknown layer violation, got: %v", violations)
	}
}

func TestRealWorkspacePassesLayerRules(t *testing.T) {
	root, err := findWorkspaceRoot()
	if err != nil {
		t.Fatalf("findWorkspaceRoot failed: %v", err)
	}
	modPath, specs, err := loadWorkspacePackages(root)
	if err != nil {
		t.Fatalf("loadWorkspacePackages failed: %v", err)
	}
	violations := checkLayerRules(modPath, specs)
	if len(violations) != 0 {
		t.Fatalf("real workspace layer violations: %v", violations)
	}
}

func TestLoadWorkspacePackagesDetectsViolationOnDisk(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module demo\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "foundation"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "domain"), 0o755); err != nil {
		t.Fatal(err)
	}
	foundationSrc := "package foundation\n\nimport _ \"demo/domain\"\n"
	if err := os.WriteFile(filepath.Join(tmp, "foundation", "bad.go"), []byte(foundationSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	domainSrc := "package domain\n"
	if err := os.WriteFile(filepath.Join(tmp, "domain", "ok.go"), []byte(domainSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	modPath, specs, err := loadWorkspacePackages(tmp)
	if err != nil {
		t.Fatalf("loadWorkspacePackages failed: %v", err)
	}
	violations := checkLayerRules(modPath, specs)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got: %v", violations)
	}
}

func TestParseSubcommand(t *testing.T) {
	for _, valid := range []string{"ci", "fmt", "layers"} {
		got, err := parseSubcommand([]string{valid})
		if err != nil || got != valid {
			t.Fatalf("parseSubcommand([%q]) = (%q, %v)", valid, got, err)
		}
	}
	if _, err := parseSubcommand(nil); err == nil {
		t.Fatal("expected error for empty args")
	}
	if _, err := parseSubcommand([]string{"unknown"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if _, err := parseSubcommand([]string{"ci", "extra"}); err == nil {
		t.Fatal("expected error for extra argument")
	}
}
