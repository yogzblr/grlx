//go:build windows

package winupdate

import (
	"fmt"
	"runtime"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// oleUpdateBackend implements updateBackend against the real Windows
// Update Agent COM API (Microsoft.Update.Session), the same object
// Salt's win_wua module drives via
// win32com.client.Dispatch("Microsoft.Update.Session"). It follows the
// COM lifecycle pattern winshortcut/com.go established: lock the
// calling goroutine to one OS thread for the apartment's lifetime,
// initialize a single-threaded apartment, and release every acquired
// IUnknown/IDispatch before CoUninitialize.
//
// The same VARIANT/IDispatch reference-counting rule documented on
// wintaskscheduler's oleTaskBackend applies here: a VT_DISPATCH
// VARIANT and the *ole.IDispatch its ToIDispatch() extracts are the
// same COM reference, so it must be released exactly once. dispatchResult
// below is this package's chokepoint for that, same as
// wintaskscheduler's.
type oleUpdateBackend struct{}

func withSession(fn func(session *ole.IDispatch) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		return fmt.Errorf("winupdate: CoInitializeEx: %w", err)
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("Microsoft.Update.Session")
	if err != nil {
		return fmt.Errorf("winupdate: create Microsoft.Update.Session: %w", err)
	}
	defer unknown.Release()

	session, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("winupdate: Microsoft.Update.Session has no IDispatch: %w", err)
	}
	defer session.Release()

	return fn(session)
}

// dispatchResult extracts the IDispatch a CallMethod/GetProperty result
// VARIANT holds, transferring the VARIANT's COM reference to the
// returned IDispatch. The caller must Release() it and must NOT also
// Clear() the source VARIANT -- see the oleUpdateBackend doc comment.
func dispatchResult(v *ole.VARIANT, err error, context string) (*ole.IDispatch, error) {
	if err != nil {
		return nil, fmt.Errorf("winupdate: %s: %w", context, err)
	}
	d := v.ToIDispatch()
	if d == nil {
		v.Clear()
		return nil, fmt.Errorf("winupdate: %s: expected an object result", context)
	}
	return d, nil
}

func getDispatchProp(disp *ole.IDispatch, name string) (*ole.IDispatch, error) {
	v, err := oleutil.GetProperty(disp, name)
	return dispatchResult(v, err, "get "+name)
}

func callDispatch(disp *ole.IDispatch, method string, args ...interface{}) (*ole.IDispatch, error) {
	v, err := oleutil.CallMethod(disp, method, args...)
	return dispatchResult(v, err, "call "+method)
}

// callVoid invokes a method whose result carries no ownership this
// package needs to keep: it Clears the result VARIANT itself since no
// IDispatch is extracted from it.
func callVoid(disp *ole.IDispatch, method string, args ...interface{}) error {
	v, err := oleutil.CallMethod(disp, method, args...)
	if err != nil {
		return fmt.Errorf("winupdate: call %s: %w", method, err)
	}
	v.Clear()
	return nil
}

func getStringProp(disp *ole.IDispatch, name string) (string, error) {
	v, err := oleutil.GetProperty(disp, name)
	if err != nil {
		return "", fmt.Errorf("winupdate: get %s: %w", name, err)
	}
	defer v.Clear()
	s, _ := v.Value().(string)
	return s, nil
}

func getIntProp(disp *ole.IDispatch, name string) (int, error) {
	v, err := oleutil.GetProperty(disp, name)
	if err != nil {
		return 0, fmt.Errorf("winupdate: get %s: %w", name, err)
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

func getBoolProp(disp *ole.IDispatch, name string) (bool, error) {
	v, err := oleutil.GetProperty(disp, name)
	if err != nil {
		return false, fmt.Errorf("winupdate: get %s: %w", name, err)
	}
	defer v.Clear()
	b, _ := v.Value().(bool)
	return b, nil
}

func setDispatchProp(disp *ole.IDispatch, name string, value *ole.IDispatch) error {
	v, err := oleutil.PutProperty(disp, name, value)
	if err != nil {
		return fmt.Errorf("winupdate: set %s: %w", name, err)
	}
	v.Clear()
	return nil
}

// createUpdateColl creates a standalone Microsoft.Update.UpdateColl
// object, used to build the update lists IUpdateDownloader.Updates and
// IUpdateInstaller.Updates expect.
func createUpdateColl() (*ole.IDispatch, error) {
	unknown, err := oleutil.CreateObject("Microsoft.Update.UpdateColl")
	if err != nil {
		return nil, fmt.Errorf("winupdate: create Microsoft.Update.UpdateColl: %w", err)
	}
	defer unknown.Release()
	disp, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, fmt.Errorf("winupdate: Microsoft.Update.UpdateColl has no IDispatch: %w", err)
	}
	return disp, nil
}

// search runs searcher.Search(criteria) and returns the ISearchResult
// and its Updates collection. The caller owns and must Release() both.
func search(session *ole.IDispatch, criteria string) (result, updates *ole.IDispatch, err error) {
	searcher, err := callDispatch(session, "CreateUpdateSearcher")
	if err != nil {
		return nil, nil, err
	}
	defer searcher.Release()

	result, err = callDispatch(searcher, "Search", criteria)
	if err != nil {
		return nil, nil, fmt.Errorf("winupdate: Search(%q): %w", criteria, err)
	}

	updates, err = getDispatchProp(result, "Updates")
	if err != nil {
		result.Release()
		return nil, nil, err
	}
	return result, updates, nil
}

// readUpdateInfo copies the fields this package needs off a live
// IUpdate object into a plain updateInfo. It does not take ownership of
// update.
func readUpdateInfo(update *ole.IDispatch) (updateInfo, error) {
	var info updateInfo
	var err error
	if info.Title, err = getStringProp(update, "Title"); err != nil {
		return info, err
	}
	if info.IsInstalled, err = getBoolProp(update, "IsInstalled"); err != nil {
		return info, err
	}
	if info.EulaAccepted, err = getBoolProp(update, "EulaAccepted"); err != nil {
		return info, err
	}

	kbColl, err := getDispatchProp(update, "KBArticleIDs")
	if err != nil {
		return info, err
	}
	defer kbColl.Release()
	kbCount, err := getIntProp(kbColl, "Count")
	if err != nil {
		return info, err
	}
	// IStringCollection, like IUpdateCollection below, is 0-based --
	// unlike Task Scheduler's Actions/Triggers collections (1-based).
	for i := 0; i < kbCount; i++ {
		v, err := oleutil.CallMethod(kbColl, "Item", i)
		if err != nil {
			return info, fmt.Errorf("winupdate: KBArticleIDs.Item(%d): %w", i, err)
		}
		kb, _ := v.Value().(string)
		v.Clear()
		if kb != "" {
			info.KBArticleIDs = append(info.KBArticleIDs, kb)
		}
	}
	return info, nil
}

// collectUpdateInfo snapshots every update in a live IUpdateCollection
// into plain updateInfo values. IUpdateCollection is 0-based (Item(0)
// is the first element) -- the opposite convention from Task
// Scheduler's Actions/Triggers collections.
func collectUpdateInfo(updates *ole.IDispatch) ([]updateInfo, error) {
	count, err := getIntProp(updates, "Count")
	if err != nil {
		return nil, err
	}
	infos := make([]updateInfo, 0, count)
	for i := 0; i < count; i++ {
		item, err := callDispatch(updates, "Item", i)
		if err != nil {
			return nil, err
		}
		info, err := readUpdateInfo(item)
		item.Release()
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (oleUpdateBackend) Search(criteria string) ([]updateInfo, error) {
	var infos []updateInfo
	err := withSession(func(session *ole.IDispatch) error {
		result, updates, err := search(session, criteria)
		if err != nil {
			return err
		}
		defer result.Release()
		defer updates.Release()

		infos, err = collectUpdateInfo(updates)
		return err
	})
	return infos, err
}

func (oleUpdateBackend) Install(criteria string, wantedKBs map[string]bool, acceptEula bool) (installOutcome, error) {
	var outcome installOutcome
	err := withSession(func(session *ole.IDispatch) error {
		result, updates, err := search(session, criteria)
		if err != nil {
			return err
		}
		defer result.Release()
		defer updates.Release()

		count, err := getIntProp(updates, "Count")
		if err != nil {
			return err
		}

		toDownload, err := createUpdateColl()
		if err != nil {
			return err
		}
		defer toDownload.Release()

		// Keep the exact live IUpdate objects that matched, so the same
		// COM instances used for filtering are the ones queued for
		// download/install -- WUA identifies updates by COM identity, not
		// by KB string, so re-fetching Item(i) later could operate on a
		// different subset if the search result changed underneath us.
		var matched []*ole.IDispatch
		defer func() {
			for _, m := range matched {
				m.Release()
			}
		}()

		for i := 0; i < count; i++ {
			item, err := callDispatch(updates, "Item", i)
			if err != nil {
				return err
			}
			info, err := readUpdateInfo(item)
			if err != nil {
				item.Release()
				return err
			}
			if info.IsInstalled || !matchesAnyKB(info, wantedKBs) {
				item.Release()
				continue
			}
			if !info.EulaAccepted {
				if !acceptEula {
					outcome.Skipped = append(outcome.Skipped, info.Title)
					item.Release()
					continue
				}
				if err := callVoid(item, "AcceptEula"); err != nil {
					item.Release()
					return fmt.Errorf("winupdate: AcceptEula(%q): %w", info.Title, err)
				}
			}
			if err := callVoid(toDownload, "Add", item); err != nil {
				item.Release()
				return fmt.Errorf("winupdate: queue download %q: %w", info.Title, err)
			}
			matched = append(matched, item)
		}

		if len(matched) == 0 {
			return nil
		}

		downloader, err := callDispatch(session, "CreateUpdateDownloader")
		if err != nil {
			return err
		}
		defer downloader.Release()
		if err := setDispatchProp(downloader, "Updates", toDownload); err != nil {
			return err
		}
		downloadResult, err := callDispatch(downloader, "Download")
		if err != nil {
			return fmt.Errorf("winupdate: Download: %w", err)
		}
		downloadResult.Release()

		toInstall, err := createUpdateColl()
		if err != nil {
			return err
		}
		defer toInstall.Release()
		// Only updates that actually downloaded go on to Install -- and
		// outcome.Installed is built from this same queuedTitles list, not
		// from every matched update, so an update that failed to download
		// is never misreported as installed.
		var queuedTitles []string
		for _, item := range matched {
			downloaded, err := getBoolProp(item, "IsDownloaded")
			if err != nil {
				return err
			}
			if !downloaded {
				continue
			}
			if err := callVoid(toInstall, "Add", item); err != nil {
				return fmt.Errorf("winupdate: queue install: %w", err)
			}
			title, _ := getStringProp(item, "Title")
			queuedTitles = append(queuedTitles, title)
		}

		if len(queuedTitles) == 0 {
			return nil
		}

		installer, err := callDispatch(session, "CreateUpdateInstaller")
		if err != nil {
			return err
		}
		defer installer.Release()
		if err := setDispatchProp(installer, "Updates", toInstall); err != nil {
			return err
		}
		installResult, err := callDispatch(installer, "Install")
		if err != nil {
			return fmt.Errorf("winupdate: Install: %w", err)
		}
		defer installResult.Release()

		// installResult.RebootRequired is an aggregate flag; per-update
		// result codes (installResult.GetUpdateResult(i).ResultCode) are
		// not checked here -- a known scope limitation, see the package
		// doc comment.
		if outcome.RebootRequired, err = getBoolProp(installResult, "RebootRequired"); err != nil {
			return err
		}
		outcome.Installed = queuedTitles

		return nil
	})
	return outcome, err
}
