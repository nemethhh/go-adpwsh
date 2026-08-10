package adscript

import (
	"encoding/json"
	"testing"
)

// -Remove → -Add → -Replace → -Clear is AD's execution order, not ours. A name
// in two operations means the caller's intent is ambiguous under that order,
// so the builder refuses instead of relying on the ordering being what the
// user meant.
func TestAttrOpsRejectsContradictions(t *testing.T) {
	tests := []struct {
		name  string
		build func(*AttrOps)
	}{
		{"replace and clear", func(o *AttrOps) { o.ReplaceValue("description", "x"); o.ClearName("description") }},
		{"remove and clear", func(o *AttrOps) { o.RemoveValues("otherPager", "1"); o.ClearName("otherPager") }},
		{"add and replace", func(o *AttrOps) { o.AddValues("url", "a"); o.ReplaceValue("url", "b") }},
		{"case-insensitive", func(o *AttrOps) { o.ReplaceValue("Description", "x"); o.ClearName("description") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var o AttrOps
			tt.build(&o)
			err := o.Apply(map[string]any{})
			if err == nil {
				t.Fatal("Apply must reject an attribute named in two operations")
			}
			var ce *ConflictError
			if !asConflict(err, &ce) {
				t.Fatalf("want a *ConflictError, got %T: %v", err, err)
			}
			if len(ce.Ops) != 2 {
				t.Errorf("ConflictError.Ops = %v, want exactly the two operations", ce.Ops)
			}
		})
	}
}

func TestAttrOpsCombinedPayload(t *testing.T) {
	var o AttrOps
	o.RemoveValues("otherPager", "555-0100")
	o.AddValues("otherPager", "555-0199", "555-0200")
	o.ReplaceValue("description", `O'Brien, "Bob" & co; $x`)
	o.ClearName("displayName")

	splat := map[string]any{"Identity": "9f2c"}
	if err := o.Apply(splat); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, err := json.Marshal(splat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// encoding/json HTML-escapes the ampersand to \u0026 (and would do the same
	// to < and >). That is lossless — ConvertFrom-Json decodes it back to the
	// exact byte the caller passed — and it is one more reason a shell
	// metacharacter in a value can never become script text.
	want := `{"Add":{"otherPager":["555-0199","555-0200"]},` +
		`"Clear":["displayName"],` +
		`"Identity":"9f2c",` +
		`"Remove":{"otherPager":["555-0100"]},` +
		`"Replace":{"description":"O'Brien, \"Bob\" \u0026 co; $x"}}`
	if string(got) != want {
		t.Errorf("payload =\n%s\nwant\n%s", got, want)
	}
}

func TestAttrOpsEmptyApplyIsNoop(t *testing.T) {
	var o AttrOps
	splat := map[string]any{"Identity": "9f2c"}
	if err := o.Apply(splat); err != nil {
		t.Fatal(err)
	}
	if len(splat) != 1 {
		t.Errorf("empty AttrOps must add nothing, got %v", splat)
	}
}

func TestAttrOpsIsEmpty(t *testing.T) {
	var o AttrOps
	if !o.IsEmpty() {
		t.Error("zero AttrOps must be empty")
	}
	o.ClearName("description")
	if o.IsEmpty() {
		t.Error("AttrOps with a Clear must not be empty")
	}
}

func asConflict(err error, out **ConflictError) bool {
	c, ok := err.(*ConflictError)
	if ok {
		*out = c
	}
	return ok
}
