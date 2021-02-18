package extended_uuid

import (
	"testing"
)

func TestParseExUUid(t *testing.T) {
	exUuid, err := Parse("b2037c24-5470e945-cf6d-456c-9985-d58f6b8dca71", true)

	t.Helper()
	if err != nil {
		t.Error("Fail to parse exUuid")
	}
	uuidText := exUuid.Uuid.String()
	if uuidText != "5470e945-cf6d-456c-9985-d58f6b8dca71" {
		t.Error("Fail to parse exUuid")
	}
}
