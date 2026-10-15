package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWriteSubnetRoutesRepairsMalformedContent(t *testing.T) {
	for _, routes := range [][]string{{"192.168.50.0/24"}, {}} {
		path := filepath.Join(t.TempDir(), "subnet-routes")
		t.Setenv("SUBNET_ROUTES_FILE", path)
		if err := os.WriteFile(path, []byte("192.168.31.0/24,broken"), 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := readSubnetRoutesFile(); err == nil {
			t.Fatal("malformed content must still fail reads")
		}
		if changed, err := writeSubnetRoutesFile(routes); err != nil || !changed {
			t.Fatalf("repair: changed=%v err=%v", changed, err)
		}
		if got, err := readSubnetRoutesFile(); err != nil || !reflect.DeepEqual(got, routes) {
			t.Fatalf("read after repair: %v %v", got, err)
		}
		if changed, err := writeSubnetRoutesFile(routes); err != nil || changed {
			t.Fatalf("unchanged: changed=%v err=%v", changed, err)
		}
	}
}

func TestWriteSubnetRoutesPreservesReadErrors(t *testing.T) {
	// Reading a directory fails even when tests run as root.
	path := t.TempDir()
	t.Setenv("SUBNET_ROUTES_FILE", path)
	if changed, err := writeSubnetRoutesFile([]string{}); err == nil || changed {
		t.Fatalf("read failure ignored: changed=%v err=%v", changed, err)
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("original path modified: %v", err)
	}
}
