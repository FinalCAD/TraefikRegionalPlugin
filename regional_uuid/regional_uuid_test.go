package regional_uuid

import "testing"

func testReadRegionalUuid(t *testing.T) {
	regionalUuid, err := Regional.Read("b2037c24-5470e945-cf6d-456c-9985-d58f6b8dca71", true)

	if err != nil {
		t.Error(err)
	}
	if regionalUuid.Version != 1 {
		t.Error("bad version")
	}
	if regionalUuid.Region != 1 {
		t.Error("bad region")
	}
	if regionalUuid.EntityType != 3 {
		t.Error("bad entity type")
	}
}
