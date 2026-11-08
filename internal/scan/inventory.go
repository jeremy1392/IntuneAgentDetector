package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"

	"detectoragent/internal/catalog"
	"detectoragent/internal/model"
)

const (
	appxAllUserStore     = `SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore`
	userAppxRepository   = `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`
	uninstallKey         = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	uninstallKeyWow64    = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	userUninstallKey     = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	servicesKey          = `SYSTEM\CurrentControlSet\Services`
	maxHistoryChildren   = 500
	maxModelNames        = 15
	maxMCPConfigBytes    = 8 << 20
	maxManifestBytes     = 1 << 20
	maxDirEntriesPerScan = 5000
)

var extensionIDPattern = regexp.MustCompile(`^(.+?)-\d+\.\d+`)

// inventory runs every catalog-driven inventory collector.
func inventory(cat *catalog.Catalog, profiles []Profile, currentSID string, since time.Time) []ToolEvidence {
	collectors := []func() []ToolEvidence{
		func() []ToolEvidence { return appxPackages(cat, profiles, currentSID) },
		func() []ToolEvidence { return uninstallEntries(cat, profiles, currentSID) },
		func() []ToolEvidence { return serviceEntries(cat) },
		func() []ToolEvidence { return vscodeExtensions(cat, profiles) },
		func() []ToolEvidence { return jetbrainsPlugins(cat, profiles) },
		func() []ToolEvidence { return browserExtensions(cat, profiles) },
		func() []ToolEvidence { return npmPackages(cat, profiles) },
		func() []ToolEvidence { return pipPackages(cat, profiles) },
		func() []ToolEvidence { return toolPaths(cat, profiles, since) },
	}
	results := make([][]ToolEvidence, len(collectors))
	var wg sync.WaitGroup
	for i, f := range collectors {
		wg.Add(1)
		go func(i int, f func() []ToolEvidence) {
			defer wg.Done()
			defer func() { _ = recover() }()
			results[i] = f()
		}(i, f)
	}
	wg.Wait()
	var out []ToolEvidence
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

func evidence(kind, detail, path string, level model.Level, conf model.Confidence) model.Evidence {
	return model.Evidence{Kind: kind, Detail: detail, Path: path, Level: level, Confidence: conf}
}

// ---------------------------------------------------------------- MSIX/AppX

func appxPackages(cat *catalog.Catalog, profiles []Profile, currentSID string) []ToolEvidence {
	type key struct{ tool, sid, family string }
	seen := map[key]bool{}
	var out []ToolEvidence
	add := func(sid, full string) {
		family := familyFromFullName(full)
		if family == "" {
			return
		}
		for _, t := range cat.Tools {
			if !t.MatchPackage(family) {
				continue
			}
			k := key{t.ID, sid, family}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, ToolEvidence{ToolID: t.ID, UserSID: sid,
				Evidence: evidence("appx", "MSIX package "+full, "", model.LevelInstalled, model.ConfidenceHigh)})
		}
	}
	// The user's own repository reflects the installed version; read it first.
	// AppxAllUserStore also covers users whose hive is not loaded, but may
	// keep entries of older versions.
	for i := range profiles {
		p := &profiles[i]
		if k, ok := userKey(p, currentSID, userAppxRepository, registry.ENUMERATE_SUB_KEYS); ok {
			pkgs, _ := k.ReadSubKeyNames(-1)
			for _, full := range pkgs {
				add(p.SID, full)
			}
			k.Close()
		}
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, appxAllUserStore, registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := k.ReadSubKeyNames(-1)
		for _, sid := range sids {
			if !isUserSID(sid) {
				continue
			}
			if sk, err := registry.OpenKey(k, sid, registry.ENUMERATE_SUB_KEYS); err == nil {
				pkgs, _ := sk.ReadSubKeyNames(-1)
				for _, full := range pkgs {
					add(sid, full)
				}
				sk.Close()
			}
		}
		k.Close()
	}
	return out
}

// ------------------------------------------------------- installed programs

func uninstallEntries(cat *catalog.Catalog, profiles []Profile, currentSID string) []ToolEvidence {
	var out []ToolEvidence
	scanKey := func(k registry.Key, sid string) {
		names, _ := k.ReadSubKeyNames(-1)
		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			display, _, _ := sk.GetStringValue("DisplayName")
			version, _, _ := sk.GetStringValue("DisplayVersion")
			location, _, _ := sk.GetStringValue("InstallLocation")
			sk.Close()
			if display == "" {
				continue
			}
			for _, t := range cat.Tools {
				if t.MatchUninstall(display) {
					detail := strings.TrimSpace("installed program: " + display + " " + version)
					out = append(out, ToolEvidence{ToolID: t.ID, UserSID: sid,
						Evidence: evidence("uninstall", detail, location, model.LevelInstalled, model.ConfidenceHigh)})
				}
			}
		}
	}
	for _, path := range []string{uninstallKey, uninstallKeyWow64} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS); err == nil {
			scanKey(k, "")
			k.Close()
		}
	}
	for i := range profiles {
		p := &profiles[i]
		if k, ok := userKey(p, currentSID, userUninstallKey, registry.ENUMERATE_SUB_KEYS); ok {
			scanKey(k, p.SID)
			k.Close()
		}
	}
	return out
}

// ------------------------------------------------------------------ services

func serviceEntries(cat *catalog.Catalog) []ToolEvidence {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []ToolEvidence
	for _, n := range names {
		for _, t := range cat.Tools {
			if !t.MatchService(n) {
				continue
			}
			image := ""
			if sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE); err == nil {
				image, _, _ = sk.GetStringValue("ImagePath")
				sk.Close()
			}
			out = append(out, ToolEvidence{ToolID: t.ID,
				Evidence: evidence("service", "Windows service "+n, strings.Trim(image, `"`), model.LevelInstalled, model.ConfidenceHigh)})
		}
	}
	return out
}

// ---------------------------------------------------------- IDE extensions

// parseExtensionID turns "anthropic.claude-code-2.1.319-win32-x64" into
// "anthropic.claude-code".
func parseExtensionID(dir string) string {
	m := extensionIDPattern.FindStringSubmatch(dir)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1])
}

func vscodeExtensions(cat *catalog.Catalog, profiles []Profile) []ToolEvidence {
	type key struct{ tool, sid, dir string }
	seen := map[key]bool{}
	var out []ToolEvidence
	for i := range profiles {
		p := &profiles[i]
		for _, pattern := range cat.Generic.VSCodeExtensionDirs {
			for _, dir := range expandGlob(pattern, p) {
				for _, name := range subdirs(dir) {
					id := parseExtensionID(name)
					if id == "" {
						continue
					}
					for _, t := range cat.Tools {
						if !t.MatchVSCodeExtension(id) {
							continue
						}
						k := key{t.ID, p.SID, dir}
						if seen[k] {
							continue
						}
						seen[k] = true
						out = append(out, ToolEvidence{ToolID: t.ID, UserSID: p.SID,
							Evidence: evidence("extension", "IDE extension "+id+" ("+name+")", filepath.Join(dir, name),
								model.LevelInstalled, model.ConfidenceHigh)})
					}
				}
			}
		}
	}
	return out
}

func jetbrainsPlugins(cat *catalog.Catalog, profiles []Profile) []ToolEvidence {
	var out []ToolEvidence
	for i := range profiles {
		p := &profiles[i]
		for _, pattern := range cat.Generic.JetBrainsPluginDirs {
			for _, dir := range expandGlob(pattern, p) {
				for _, name := range subdirs(dir) {
					for _, t := range cat.Tools {
						if t.MatchJetBrainsPlugin(name) {
							out = append(out, ToolEvidence{ToolID: t.ID, UserSID: p.SID,
								Evidence: evidence("extension", "JetBrains plugin "+name, filepath.Join(dir, name),
									model.LevelInstalled, model.ConfidenceMedium)})
						}
					}
				}
			}
		}
	}
	return out
}

// ------------------------------------------------------ browser extensions

func browserExtensions(cat *catalog.Catalog, profiles []Profile) []ToolEvidence {
	var out []ToolEvidence
	for i := range profiles {
		p := &profiles[i]
		for _, pattern := range cat.Generic.BrowserProfileDirs {
			for _, root := range expandGlob(pattern, p) {
				browser := browserLabel(root)
				for _, prof := range subdirs(root) {
					if prof != "Default" && !strings.HasPrefix(prof, "Profile ") {
						continue
					}
					extRoot := filepath.Join(root, prof, "Extensions")
					for _, extID := range subdirs(extRoot) {
						name, version := extensionName(filepath.Join(extRoot, extID))
						if name == "" {
							continue
						}
						for _, t := range cat.Tools {
							if !t.MatchBrowserExtension(name) {
								continue
							}
							out = append(out, ToolEvidence{
								ToolID:   t.ID + ":" + extID,
								ToolName: name + " (" + browser + " extension)",
								UserSID:  p.SID,
								Evidence: evidence("browser-extension",
									fmt.Sprintf("%s extension %q %s (id %s, profile %s)", browser, name, version, extID, prof),
									filepath.Join(extRoot, extID), model.LevelInstalled, model.ConfidenceMedium),
							})
						}
					}
				}
			}
		}
	}
	return out
}

func browserLabel(root string) string {
	l := strings.ToLower(root)
	switch {
	case strings.Contains(l, `\microsoft\edge`):
		return "Edge"
	case strings.Contains(l, `\bravesoftware`):
		return "Brave"
	case strings.Contains(l, `\chromium`):
		return "Chromium"
	default:
		return "Chrome"
	}
}

// extensionName reads the display name of the newest installed version of a
// Chromium extension, resolving __MSG_key__ placeholders.
func extensionName(extDir string) (name, version string) {
	versions := subdirs(extDir)
	if len(versions) == 0 {
		return "", ""
	}
	sort.Strings(versions)
	version = versions[len(versions)-1]
	vdir := filepath.Join(extDir, version)
	var manifest struct {
		Name          string `json:"name"`
		DefaultLocale string `json:"default_locale"`
	}
	if !readJSON(filepath.Join(vdir, "manifest.json"), maxManifestBytes, &manifest) {
		return "", version
	}
	name = manifest.Name
	if strings.HasPrefix(name, "__MSG_") && strings.HasSuffix(name, "__") {
		key := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__"))
		name = ""
		for _, loc := range []string{manifest.DefaultLocale, "en", "en_US"} {
			if loc == "" {
				continue
			}
			var msgs map[string]struct {
				Message string `json:"message"`
			}
			if readJSON(filepath.Join(vdir, "_locales", loc, "messages.json"), maxManifestBytes, &msgs) {
				for k, v := range msgs {
					if strings.ToLower(k) == key {
						name = v.Message
						break
					}
				}
			}
			if name != "" {
				break
			}
		}
	}
	return strings.TrimSpace(name), version
}

// ---------------------------------------------------------- npm and pip

func npmPackages(cat *catalog.Catalog, profiles []Profile) []ToolEvidence {
	var out []ToolEvidence
	visit := func(dir, sid string) {
		for _, name := range subdirs(dir) {
			pkgs := []string{name}
			if strings.HasPrefix(name, "@") {
				pkgs = nil
				for _, sub := range subdirs(filepath.Join(dir, name)) {
					pkgs = append(pkgs, name+"/"+sub)
				}
			}
			for _, pkg := range pkgs {
				for _, t := range cat.Tools {
					if t.MatchNPM(pkg) {
						out = append(out, ToolEvidence{ToolID: t.ID, UserSID: sid,
							Evidence: evidence("npm", "global npm package "+pkg, filepath.Join(dir, filepath.FromSlash(pkg)),
								model.LevelInstalled, model.ConfidenceHigh)})
					}
				}
			}
		}
	}
	forEachDir(cat.Generic.NPMGlobalDirs, profiles, visit)
	return out
}

func pipPackages(cat *catalog.Catalog, profiles []Profile) []ToolEvidence {
	var out []ToolEvidence
	match := func(dist, path, sid, how string) {
		for _, t := range cat.Tools {
			if t.MatchPIP(dist) {
				out = append(out, ToolEvidence{ToolID: t.ID, UserSID: sid,
					Evidence: evidence("pip", how+" "+catalog.NormalizePipName(dist), path,
						model.LevelInstalled, model.ConfidenceHigh)})
			}
		}
	}
	forEachDir(cat.Generic.PIPSiteDirs, profiles, func(dir, sid string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for i, e := range entries {
			if i > maxDirEntriesPerScan {
				break
			}
			n := e.Name()
			if !e.IsDir() || !(strings.HasSuffix(n, ".dist-info") || strings.HasSuffix(n, ".egg-info")) {
				continue
			}
			base := strings.TrimSuffix(strings.TrimSuffix(n, ".dist-info"), ".egg-info")
			if j := strings.IndexByte(base, '-'); j > 0 {
				base = base[:j]
			}
			match(base, filepath.Join(dir, n), sid, "Python package")
		}
	})
	forEachDir(cat.Generic.PIPToolDirs, profiles, func(dir, sid string) {
		for _, name := range subdirs(dir) {
			match(name, filepath.Join(dir, name), sid, "Python tool")
		}
	})
	return out
}

// forEachDir expands machine patterns once and profile patterns per profile.
func forEachDir(patterns []string, profiles []Profile, fn func(dir, sid string)) {
	for _, pattern := range patterns {
		if isProfilePattern(pattern) {
			for i := range profiles {
				for _, dir := range expandGlob(pattern, &profiles[i]) {
					fn(dir, profiles[i].SID)
				}
			}
			continue
		}
		for _, dir := range expandGlob(pattern, nil) {
			fn(dir, "")
		}
	}
}

// --------------------------------------------------------- tool file paths

func toolPaths(cat *catalog.Catalog, profiles []Profile, since time.Time) []ToolEvidence {
	var out []ToolEvidence
	for _, t := range cat.Tools {
		eachPath := func(patterns []string, fn func(path, sid string)) {
			forEachDir(patterns, profiles, fn)
		}
		eachPath(t.Installed, func(path, sid string) {
			out = append(out, ToolEvidence{ToolID: t.ID, UserSID: sid,
				Evidence: evidence("file", "installed at "+path, path, model.LevelInstalled, model.ConfidenceHigh)})
		})
		eachPath(t.Residue, func(path, sid string) {
			out = append(out, ToolEvidence{ToolID: t.ID, UserSID: sid,
				Evidence: evidence("residue", "tool data at "+path, path, model.LevelResidue, model.ConfidenceMedium)})
		})
		eachPath(t.History, func(path, sid string) {
			last := lastActivity(path)
			if last.IsZero() || last.Before(since) {
				return
			}
			e := evidence("history", "last activity "+last.Format(time.RFC3339)+" in "+path, path, model.LevelRecent, model.ConfidenceHigh)
			e.Time = &last
			out = append(out, ToolEvidence{ToolID: t.ID, UserSID: sid, Evidence: e})
		})
		eachPath(t.Models, func(path, sid string) {
			out = append(out, ToolEvidence{ToolID: t.ID, UserSID: sid,
				Evidence: evidence("models", "local model "+modelLabel(path), path, model.LevelInstalled, model.ConfidenceMedium)})
		})
		eachPath(t.MCPConfigs, func(path, sid string) {
			n := countMCPServers(path)
			if n == 0 {
				return
			}
			out = append(out, ToolEvidence{ToolID: t.ID, UserSID: sid,
				Evidence: evidence("mcp-config", fmt.Sprintf("%d MCP server(s) configured in %s", n, path), path,
					model.LevelInstalled, model.ConfidenceMedium)})
		})
	}
	return capModelEvidence(out)
}

// lastActivity returns the newest modification time of a file, or of a
// directory and its direct children. File contents are never read.
func lastActivity(path string) time.Time {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	last := st.ModTime()
	if !st.IsDir() {
		return last
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return last
	}
	for i, e := range entries {
		if i >= maxHistoryChildren {
			break
		}
		if info, err := e.Info(); err == nil && info.ModTime().After(last) {
			last = info.ModTime()
		}
	}
	return last
}

// modelLabel renders "llama3.2:3b" for Ollama manifests and the base name otherwise.
func modelLabel(path string) string {
	name := filepath.Base(path)
	if tags := listNames(path, 3); len(tags) > 0 && strings.Contains(strings.ToLower(path), `registry.ollama.ai`) {
		labels := make([]string, len(tags))
		for i, tag := range tags {
			labels[i] = name + ":" + tag
		}
		return strings.Join(labels, ", ")
	}
	return strings.TrimPrefix(name, "models--")
}

func listNames(dir string, max int) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if len(out) >= max {
			break
		}
		out = append(out, e.Name())
	}
	return out
}

// capModelEvidence keeps at most maxModelNames model entries per tool and user.
func capModelEvidence(in []ToolEvidence) []ToolEvidence {
	counts := map[string]int{}
	out := in[:0]
	for _, te := range in {
		if te.Evidence.Kind == "models" {
			k := te.ToolID + "|" + te.UserSID
			counts[k]++
			if counts[k] > maxModelNames {
				continue
			}
		}
		out = append(out, te)
	}
	return out
}

// countMCPServers counts the MCP servers declared in a JSON config file
// ("mcpServers" or "servers" objects, including per-project sections).
// Only the number of servers is kept.
func countMCPServers(path string) int {
	var doc map[string]any
	if !readJSON(path, maxMCPConfigBytes, &doc) {
		return 0
	}
	count := 0
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		m, ok := v.(map[string]any)
		if !ok || depth > 3 {
			return
		}
		for k, child := range m {
			switch k {
			case "mcpServers", "servers":
				if servers, ok := child.(map[string]any); ok {
					count += len(servers)
				}
			case "projects":
				if projects, ok := child.(map[string]any); ok {
					for _, p := range projects {
						walk(p, depth+1)
					}
				}
			}
		}
	}
	walk(doc, 0)
	return count
}

func readJSON(path string, limit int64, v any) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return false
	}
	data = trimBOM(data)
	return json.Unmarshal(data, v) == nil
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}
