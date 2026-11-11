// Package main provides workspace automation tasks (`go run ./xtask <subcommand>`).
package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type layer int

const (
	layerFoundation layer = iota
	layerDomain
	layerAdapters
	layerApps
)

func (l layer) String() string {
	switch l {
	case layerFoundation:
		return "foundation"
	case layerDomain:
		return "domain"
	case layerAdapters:
		return "adapters"
	case layerApps:
		return "apps"
	default:
		return "unknown"
	}
}

func parseLayerFromDir(relDir string) (layer, bool) {
	cleaned := strings.Trim(filepath.ToSlash(relDir), "/")
	if cleaned == "" || cleaned == "." {
		return 0, false
	}
	first := strings.Split(cleaned, "/")[0]
	switch first {
	case "foundation":
		return layerFoundation, true
	case "domain":
		return layerDomain, true
	case "adapters":
		return layerAdapters, true
	case "apps":
		return layerApps, true
	default:
		return 0, false
	}
}

type packageSpec struct {
	importPath string
	relDir     string
	imports    []string
}

func checkLayerRules(modulePath string, specs []packageSpec) []string {
	var violations []string
	pkgLayers := make(map[string]layer, len(specs))

	for _, spec := range specs {
		normDir := strings.Trim(filepath.ToSlash(spec.relDir), "/")
		if normDir == "xtask" || strings.HasPrefix(normDir, "xtask/") {
			continue
		}
		l, ok := parseLayerFromDir(normDir)
		if !ok {
			violations = append(
				violations,
				fmt.Sprintf(
					"package %q in %q does not belong to a known layer directory (expected foundation, domain, adapters, or apps)",
					spec.importPath,
					spec.relDir,
				),
			)
			continue
		}
		pkgLayers[spec.importPath] = l
	}

	modPrefix := strings.TrimRight(modulePath, "/") + "/"
	for _, spec := range specs {
		srcLayer, ok := pkgLayers[spec.importPath]
		if !ok {
			continue
		}
		for _, imp := range spec.imports {
			if imp == spec.importPath {
				continue
			}
			targetLayer, isKnown := pkgLayers[imp]
			if !isKnown && strings.HasPrefix(imp, modPrefix) {
				relImp := strings.TrimPrefix(imp, modPrefix)
				if l, parsed := parseLayerFromDir(relImp); parsed {
					targetLayer = l
					isKnown = true
				} else if relImp == "xtask" || strings.HasPrefix(relImp, "xtask/") {
					violations = append(
						violations,
						fmt.Sprintf(
							"layer violation: package %q (layer %q) cannot import automation package %q",
							spec.importPath,
							srcLayer.String(),
							imp,
						),
					)
					continue
				}
			}
			if isKnown && targetLayer >= srcLayer {
				violations = append(
					violations,
					fmt.Sprintf(
						"layer violation: package %q (layer %q) cannot import %q (layer %q; allowed: strictly lower layers than %q)",
						spec.importPath,
						srcLayer.String(),
						imp,
						targetLayer.String(),
						srcLayer.String(),
					),
				)
			}
		}
	}

	sort.Strings(violations)
	return violations
}

func readModulePath(root string) (string, error) {
	goModPath := filepath.Join(root, "go.mod")
	raw, err := os.ReadFile(goModPath)
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
		if strings.HasPrefix(trimmed, "module ") {
			mod := strings.TrimSpace(strings.TrimPrefix(trimmed, "module "))
			mod = strings.Trim(mod, `"`)
			if mod != "" {
				return mod, nil
			}
		}
	}
	return "", fmt.Errorf("missing module directive in %s", goModPath)
}

func loadWorkspacePackages(root string) (string, []packageSpec, error) {
	modulePath, err := readModulePath(root)
	if err != nil {
		return "", nil, err
	}

	dirImports := make(map[string]map[string]struct{})
	fset := token.NewFileSet()

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name != "." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "vendor" || name == "bin" || name == "dist") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		relFile, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relDir := filepath.ToSlash(filepath.Dir(relFile))
		if relDir == "." {
			return fmt.Errorf("root directory must not contain Go source file %q", relFile)
		}

		parsedFile, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relFile, err)
		}
		impSet, exists := dirImports[relDir]
		if !exists {
			impSet = make(map[string]struct{})
			dirImports[relDir] = impSet
		}
		for _, impSpec := range parsedFile.Imports {
			impPath := strings.Trim(impSpec.Path.Value, `"`)
			if impPath != "" {
				impSet[impPath] = struct{}{}
			}
		}
		return nil
	})
	if walkErr != nil {
		return "", nil, walkErr
	}

	dirs := make([]string, 0, len(dirImports))
	for dir := range dirImports {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	specs := make([]packageSpec, 0, len(dirs))
	for _, dir := range dirs {
		impSet := dirImports[dir]
		imports := make([]string, 0, len(impSet))
		for imp := range impSet {
			imports = append(imports, imp)
		}
		sort.Strings(imports)
		specs = append(specs, packageSpec{
			importPath: modulePath + "/" + dir,
			relDir:     dir,
			imports:    imports,
		})
	}
	return modulePath, specs, nil
}

func runLayers(root string) error {
	modulePath, specs, err := loadWorkspacePackages(root)
	if err != nil {
		return err
	}
	violations := checkLayerRules(modulePath, specs)
	if len(violations) > 0 {
		return errors.New(strings.Join(violations, "\n"))
	}
	fmt.Printf("layer check passed (%d packages verified)\n", len(specs))
	return nil
}

func runCommand(root, name string, args ...string) error {
	fmt.Printf("+ %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command `%s %s` failed: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func runGofmtCheck(root string) error {
	fmt.Println("+ gofmt -e -l .")
	cmd := exec.Command("gofmt", "-e", "-l", ".")
	cmd.Dir = root
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	output := strings.TrimSpace(out.String())
	if err != nil {
		if output != "" {
			return fmt.Errorf("gofmt -e -l . failed:\n%s", output)
		}
		return fmt.Errorf("gofmt -e -l . failed: %w", err)
	}
	if output != "" {
		return fmt.Errorf("the following files are not gofmt-formatted:\n%s", output)
	}
	return nil
}

func parseSubcommand(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("missing xtask subcommand (expected: `ci`, `fmt`, or `layers`)")
	}
	if len(args) > 1 {
		return "", fmt.Errorf("unexpected extra argument %q", args[1])
	}
	switch args[0] {
	case "ci", "fmt", "layers":
		return args[0], nil
	default:
		return "", fmt.Errorf("unknown xtask subcommand %q (expected: `ci`, `fmt`, or `layers`)", args[0])
	}
}

func findWorkspaceRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		if info, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("could not locate go.mod from %s", cwd)
}

func run(args []string) error {
	sub, err := parseSubcommand(args)
	if err != nil {
		return err
	}
	root, err := findWorkspaceRoot()
	if err != nil {
		return err
	}
	switch sub {
	case "ci":
		if err := runGofmtCheck(root); err != nil {
			return err
		}
		if err := runCommand(root, "go", "vet", "./..."); err != nil {
			return err
		}
		if err := runCommand(root, "golangci-lint", "run", "./..."); err != nil {
			return err
		}
		if err := runCommand(root, "go", "build", "./..."); err != nil {
			return err
		}
		if err := runCommand(root, "go", "test", "./..."); err != nil {
			return err
		}
		return runLayers(root)
	case "fmt":
		return runCommand(root, "gofmt", "-w", ".")
	case "layers":
		return runLayers(root)
	default:
		return fmt.Errorf("unhandled subcommand %q", sub)
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
