package regional_uuid

import (
	"errors"
	"github.com/FinalCAD/TraefikRegionalPlugin/extended_uuid"
	"github.com/google/uuid"
)

type RegionalUuid struct {
	Uuid       *uuid.UUID
	Region     byte
	EntityType byte
	Version    byte
}

type regionalUuid struct{}

var Regional regionalUuid

func (regionalUuid) Read(exUuidText string, isLittleEndian bool) (*RegionalUuid, error) {
	exUuid, err := extended_uuid.Parse(exUuidText, isLittleEndian)
	if err != nil {
		return &RegionalUuid{}, errors.New("fail to parse exUuid")
	}
	exUuidReader := extended_uuid.NewExUuidReader(exUuid, isLittleEndian)
	version := exUuidReader.ReadByte()
	region := exUuidReader.ReadByte()
	entityType := exUuidReader.ReadByte()
	return &RegionalUuid{
		Version:    version,
		Region:     region,
		EntityType: entityType,
		Uuid:       exUuid.Uuid,
	}, nil
}
