package envoyauth

import (
	"context"
	"reflect"
	"testing"

	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

func TestGetRevisionLegacy(t *testing.T) {
	store := inmem.New()
	ctx := context.Background()

	result := EvalResult{}

	tb := bundle.Manifest{
		Revision: "abc123",
		Roots:    &[]string{"/a/b", "/a/c"},
	}

	// write a "legacy" manifest
	err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
		if err := bundle.LegacyWriteManifestToStore(ctx, store, txn, tb); err != nil {
			t.Fatalf("Failed to write manifest to store: %s", err)
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Unexpected error finishing transaction: %s", err)
	}

	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)

	err = getRevision(ctx, store, txn, &result)
	if err != nil {
		t.Fatal(err)
	}

	expected := "abc123"
	if result.Revision != "abc123" {
		t.Fatalf("Expected revision %v but got %v", expected, result.Revision)
	}

	if len(result.Revisions) != 0 {
		t.Fatal("Unexpected multiple bundles")
	}
}

func TestGetRevisionMulti(t *testing.T) {
	store := inmem.New()
	ctx := context.Background()

	result := EvalResult{}

	bundles := map[string]bundle.Manifest{
		"bundle1": {
			Revision: "abc123",
			Roots:    &[]string{"/a/b", "/a/c"},
		},
		"bundle2": {
			Revision: "def123",
			Roots:    &[]string{"/x/y", "/z"},
		},
	}

	// write bundles
	for name, manifest := range bundles {
		err := storage.Txn(ctx, store, storage.WriteParams, func(txn storage.Transaction) error {
			err := bundle.WriteManifestToStore(ctx, store, txn, name, manifest)
			if err != nil {
				t.Fatalf("Failed to write manifest to store: %s", err)
			}
			return err
		})
		if err != nil {
			t.Fatalf("Unexpected error finishing transaction: %s", err)
		}
	}

	txn := storage.NewTransactionOrDie(ctx, store, storage.WriteParams)

	err := getRevision(ctx, store, txn, &result)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Revisions) != 2 {
		t.Fatalf("Expected two bundles but got %v", len(result.Revisions))
	}

	expected := map[string]string{"bundle1": "abc123", "bundle2": "def123"}
	if !reflect.DeepEqual(result.Revisions, expected) {
		t.Fatalf("Expected result: %v, got: %v", expected, result.Revisions)
	}

	if result.Revision != "" {
		t.Fatalf("Unexpected revision %v", result.Revision)
	}

}
