package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"strings"
)

const (
	StartKeyWord = "Bearer"
)

type Token struct {
	Header  map[string]string
	Payload map[string]string
}

func toMap(fragment string) (map[string]string, error) {
	var newMap map[string]string
	if l := len(fragment) % 4; l > 0 {
		fragment += strings.Repeat("=", 4-l)
	}

	decodedBytes, err := base64.URLEncoding.DecodeString(fragment)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	json.Unmarshal(decodedBytes, &newMap)
	return newMap, nil
}

func Parse(token string) (*Token, error) {
	if !strings.HasPrefix(token, StartKeyWord) {
		return nil, errors.New("token not supported")
	}
	fragments := strings.Split(token[len(StartKeyWord)+1:], ".")
	if len(fragments) != 3 {
		return nil, errors.New("token not supported")
	}
	header, err := toMap(fragments[0])
	if err != nil {
		return nil, err
	}
	payload, err := toMap(fragments[1])
	if err != nil {
		return nil, err
	}
	return &Token{
		Header:  header,
		Payload: payload,
	}, nil
}
