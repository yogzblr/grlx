//go:build linux

package mount

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Entry is a single fstab/mtab-style mount table record.
type Entry struct {
	Device     string
	MountPoint string
	FSType     string
	Options    []string
	Dump       int
	Pass       int
}

// Line is one line of a mount table file: either a parsed Entry, or a
// comment/blank line preserved verbatim so rewrites don't clobber the rest
// of the file.
type Line struct {
	Raw   string
	Entry *Entry
}

// escaper matches the octal escapes (e.g. \040 for a space) that fstab uses
// so device/mountpoint paths containing whitespace round-trip correctly.
var fieldEscapes = map[byte]string{
	' ':  `\040`,
	'\t': `\011`,
	'\n': `\012`,
	'\\': `\134`,
}

func escapeField(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if esc, ok := fieldEscapes[s[i]]; ok {
			b.WriteString(esc)
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func unescapeField(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ParseTable parses a fstab/mtab-format file, preserving comments and blank
// lines so the same content can be written back with minimal diffs.
func ParseTable(r io.Reader) ([]Line, error) {
	var lines []Line
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, Line{Raw: raw})
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			// Malformed/unrecognised line; preserve it rather than fail the
			// whole parse.
			lines = append(lines, Line{Raw: raw})
			continue
		}
		entry := &Entry{
			Device:     unescapeField(fields[0]),
			MountPoint: unescapeField(fields[1]),
			FSType:     fields[2],
		}
		if len(fields) >= 4 && fields[3] != "" {
			entry.Options = strings.Split(fields[3], ",")
		} else {
			entry.Options = []string{"defaults"}
		}
		if len(fields) >= 5 {
			entry.Dump, _ = strconv.Atoi(fields[4])
		}
		if len(fields) >= 6 {
			entry.Pass, _ = strconv.Atoi(fields[5])
		}
		lines = append(lines, Line{Entry: entry})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// FormatEntry renders an Entry as a single fstab-format line (no trailing
// newline).
func FormatEntry(e Entry) string {
	opts := e.Options
	if len(opts) == 0 {
		opts = []string{"defaults"}
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%d\t%d",
		escapeField(e.Device), escapeField(e.MountPoint), e.FSType,
		strings.Join(opts, ","), e.Dump, e.Pass)
}

// WriteTable writes lines back out, one per line.
func WriteTable(w io.Writer, lines []Line) error {
	bw := bufio.NewWriter(w)
	for _, l := range lines {
		var err error
		if l.Entry != nil {
			_, err = fmt.Fprintln(bw, FormatEntry(*l.Entry))
		} else {
			_, err = fmt.Fprintln(bw, l.Raw)
		}
		if err != nil {
			return err
		}
	}
	return bw.Flush()
}

// FindByMountPoint returns the entry whose mount point matches, if any.
func FindByMountPoint(lines []Line, mountPoint string) *Entry {
	for _, l := range lines {
		if l.Entry != nil && l.Entry.MountPoint == mountPoint {
			return l.Entry
		}
	}
	return nil
}

// UpsertByMountPoint replaces the line for mountPoint's existing entry, or
// appends a new one if none exists. Returns the updated lines and whether a
// change was made (i.e. the entry didn't already match exactly).
func UpsertByMountPoint(lines []Line, newEntry Entry) ([]Line, bool) {
	for i, l := range lines {
		if l.Entry != nil && l.Entry.MountPoint == newEntry.MountPoint {
			if entriesEqual(*l.Entry, newEntry) {
				return lines, false
			}
			out := make([]Line, len(lines))
			copy(out, lines)
			out[i] = Line{Entry: &newEntry}
			return out, true
		}
	}
	out := make([]Line, len(lines), len(lines)+1)
	copy(out, lines)
	out = append(out, Line{Entry: &newEntry})
	return out, true
}

// RemoveByMountPoint removes the entry line for mountPoint, if present.
// Returns the updated lines and whether anything was removed.
func RemoveByMountPoint(lines []Line, mountPoint string) ([]Line, bool) {
	out := make([]Line, 0, len(lines))
	removed := false
	for _, l := range lines {
		if l.Entry != nil && l.Entry.MountPoint == mountPoint {
			removed = true
			continue
		}
		out = append(out, l)
	}
	return out, removed
}

func entriesEqual(a, b Entry) bool {
	if a.Device != b.Device || a.MountPoint != b.MountPoint || a.FSType != b.FSType ||
		a.Dump != b.Dump || a.Pass != b.Pass {
		return false
	}
	if len(a.Options) != len(b.Options) {
		return false
	}
	for i := range a.Options {
		if a.Options[i] != b.Options[i] {
			return false
		}
	}
	return true
}
