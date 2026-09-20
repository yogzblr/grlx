package file

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
)

// matchesAnyPattern reports whether relPath (slash-separated, relative to a
// copy/sync root) or its basename matches any of the given glob patterns.
// Matching the basename too lets a simple pattern like "*.tmp" work no
// matter how deep the file is nested, without requiring "**/*.tmp".
func matchesAnyPattern(patterns []string, relPath string) bool {
	if len(patterns) == 0 {
		return false
	}
	base := path.Base(relPath)
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		if ok, _ := path.Match(pat, relPath); ok {
			return true
		}
		if ok, _ := path.Match(pat, base); ok {
			return true
		}
	}
	return false
}

// stringSlice coerces a step property value into a []string, accepting both
// the []string a caller might construct directly and the []interface{}
// shape parsed YAML/JSON properties arrive in.
func stringSlice(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// listTreeFiles walks root and returns every regular file's path relative
// to root, slash-separated, after excluding anything matched by
// globPattern (applied to the whole relative tree, not just top-level
// entries) or any of exclude's patterns.
func listTreeFiles(root, globPattern string, exclude []string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if globPattern != "" {
			ok, matchErr := path.Match(globPattern, path.Base(rel))
			if matchErr != nil {
				return matchErr
			}
			if !ok {
				if ok2, _ := path.Match(globPattern, rel); !ok2 {
					return nil
				}
			}
		}
		if matchesAnyPattern(exclude, rel) {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	return out, err
}

// copyFileWithMode copies src to dst, creating dst's parent directory tree
// when mkdir is true, and reports whether dst's content changed (it is
// created, or its bytes differ from src's). When chmodX is true, the
// destination file additionally gets its executable bits set (mode |
// 0o111) regardless of whether the content itself changed. When apply is
// false, nothing is written -- the same checks and comparison run so a dry
// run reports exactly what would happen (including a missing-parent-dir
// failure), but no filesystem mutation occurs.
func copyFileWithMode(src, dst string, mkdir, chmodX, apply bool) (bool, error) {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return false, err
	}

	if _, statErr := os.Stat(filepath.Dir(dst)); os.IsNotExist(statErr) {
		if !mkdir {
			return false, ErrPathNotFound
		}
		if apply {
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return false, err
			}
		}
	}

	srcBytes, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}

	changed := true
	if dstBytes, err := os.ReadFile(dst); err == nil {
		changed = !bytes.Equal(srcBytes, dstBytes)
	}

	if !apply {
		return changed, nil
	}

	mode := srcInfo.Mode().Perm()
	if chmodX {
		mode |= 0o111
	}

	if changed {
		if err := os.WriteFile(dst, srcBytes, mode); err != nil {
			return false, err
		}
	} else if chmodX {
		if err := os.Chmod(dst, mode); err != nil {
			return false, err
		}
	}
	return changed, nil
}
