//go:build windows

package winshortcut

import (
	"fmt"
	"runtime"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// oleShortcutBackend implements shortcutBackend against the real Windows
// shell, via WScript.Shell's CreateShortcut automation object
// (IWshShortcut) — the same object Salt's win_shortcut module drives
// through win32com.client.Dispatch("WScript.Shell"). Calling
// CreateShortcut on a path that already holds a .lnk file loads its
// existing properties instead of creating a blank one, which is what
// lets Load and Save below share the same accessor.
//
// This is the smallest-scope member of G.6 (Task Scheduler and WUA
// follow), chosen specifically to establish the COM lifecycle pattern
// the other two will reuse:
//
//  1. Lock the calling goroutine to one OS thread for the entire
//     lifetime of the COM apartment. The Go scheduler is otherwise free
//     to migrate a goroutine to a different OS thread between any two
//     statements, which would silently detach the single-threaded
//     apartment CoInitializeEx just bound to the original thread —
//     the "wrong apartment threading" failure mode COM tends to punish
//     with hangs or E_NOINTERFACE rather than a clean error.
//  2. Initialize a single-threaded apartment (COINIT_APARTMENTTHREADED):
//     WScript.Shell's automation objects are STA, not free-threaded.
//  3. Release every IUnknown/IDispatch reference this file acquires
//     (CreateObject's IUnknown, its IDispatch, and the CreateShortcut
//     return value) and Clear every VARIANT it reads or writes through,
//     in the reverse order acquired, before CoUninitialize — a missed
//     Release/Clear here leaks the shell process's COM references
//     rather than failing loudly.
type oleShortcutBackend struct{}

// withShortcut initializes a single-threaded COM apartment, obtains the
// IWshShortcut for path, and runs fn against it. Every COM reference it
// acquires — the apartment itself, WScript.Shell's IUnknown and
// IDispatch, and the shortcut object — is released before withShortcut
// returns, regardless of what fn returns.
func (oleShortcutBackend) withShortcut(path string, fn func(shortcut *ole.IDispatch) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		return fmt.Errorf("winshortcut: CoInitializeEx: %w", err)
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WScript.Shell")
	if err != nil {
		return fmt.Errorf("winshortcut: create WScript.Shell: %w", err)
	}
	defer unknown.Release()

	shell, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("winshortcut: WScript.Shell has no IDispatch: %w", err)
	}
	defer shell.Release()

	result, err := oleutil.CallMethod(shell, "CreateShortcut", path)
	if err != nil {
		return fmt.Errorf("winshortcut: CreateShortcut(%q): %w", path, err)
	}
	defer result.Clear()

	shortcut := result.ToIDispatch()
	if shortcut == nil {
		return fmt.Errorf("winshortcut: CreateShortcut(%q) returned no object", path)
	}
	defer shortcut.Release()

	return fn(shortcut)
}

func getStringProp(shortcut *ole.IDispatch, name string) (string, error) {
	v, err := oleutil.GetProperty(shortcut, name)
	if err != nil {
		return "", fmt.Errorf("winshortcut: get %s: %w", name, err)
	}
	defer v.Clear()
	s, _ := v.Value().(string)
	return s, nil
}

func getIntProp(shortcut *ole.IDispatch, name string) (int, error) {
	v, err := oleutil.GetProperty(shortcut, name)
	if err != nil {
		return 0, fmt.Errorf("winshortcut: get %s: %w", name, err)
	}
	defer v.Clear()
	switch n := v.Value().(type) {
	case int32:
		return int(n), nil
	case int64:
		return int(n), nil
	case int:
		return n, nil
	default:
		return 0, nil
	}
}

func setStringProp(shortcut *ole.IDispatch, name, value string) error {
	v, err := oleutil.PutProperty(shortcut, name, value)
	if err != nil {
		return fmt.Errorf("winshortcut: set %s: %w", name, err)
	}
	defer v.Clear()
	return nil
}

func setIntProp(shortcut *ole.IDispatch, name string, value int) error {
	v, err := oleutil.PutProperty(shortcut, name, int32(value))
	if err != nil {
		return fmt.Errorf("winshortcut: set %s: %w", name, err)
	}
	defer v.Clear()
	return nil
}

func (b oleShortcutBackend) Load(path string) (shortcutState, error) {
	var state shortcutState
	err := b.withShortcut(path, func(shortcut *ole.IDispatch) error {
		var err error
		if state.TargetPath, err = getStringProp(shortcut, "TargetPath"); err != nil {
			return err
		}
		if state.Arguments, err = getStringProp(shortcut, "Arguments"); err != nil {
			return err
		}
		if state.Description, err = getStringProp(shortcut, "Description"); err != nil {
			return err
		}
		if state.WorkingDirectory, err = getStringProp(shortcut, "WorkingDirectory"); err != nil {
			return err
		}
		if state.IconLocation, err = getStringProp(shortcut, "IconLocation"); err != nil {
			return err
		}
		if state.Hotkey, err = getStringProp(shortcut, "Hotkey"); err != nil {
			return err
		}
		if state.WindowStyle, err = getIntProp(shortcut, "WindowStyle"); err != nil {
			return err
		}
		return nil
	})
	return state, err
}

func (b oleShortcutBackend) Save(path string, state shortcutState) error {
	return b.withShortcut(path, func(shortcut *ole.IDispatch) error {
		if err := setStringProp(shortcut, "TargetPath", state.TargetPath); err != nil {
			return err
		}
		if err := setStringProp(shortcut, "Arguments", state.Arguments); err != nil {
			return err
		}
		if err := setStringProp(shortcut, "Description", state.Description); err != nil {
			return err
		}
		if err := setStringProp(shortcut, "WorkingDirectory", state.WorkingDirectory); err != nil {
			return err
		}
		if state.IconLocation != "" {
			if err := setStringProp(shortcut, "IconLocation", state.IconLocation); err != nil {
				return err
			}
		}
		if err := setStringProp(shortcut, "Hotkey", state.Hotkey); err != nil {
			return err
		}
		if err := setIntProp(shortcut, "WindowStyle", state.WindowStyle); err != nil {
			return err
		}

		saveResult, err := oleutil.CallMethod(shortcut, "Save")
		if err != nil {
			return fmt.Errorf("winshortcut: Save(%q): %w", path, err)
		}
		defer saveResult.Clear()
		return nil
	})
}
