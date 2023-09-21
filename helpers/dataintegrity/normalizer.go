package dataintegrity

import (
	"encoding/json"
	"errors"

	"github.com/piprate/json-gold/ld"
)

func Normalize(src interface{}, algo string) (*string, error) {
	jsonEncoded, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	var jsonInter map[string]interface{}
	err = json.Unmarshal(jsonEncoded, &jsonInter)
	if err != nil {
		return nil, err
	}

	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.Algorithm = algo

	jsonldProc := ld.NewJsonLdProcessor()
	r, err := jsonldProc.Normalize(jsonInter, options)
	if err != nil {
		return nil, err
	}
	v, isString := r.(string)
	if !isString {
		return nil, errors.New("can't normalize as a string")
	}

	return &v, nil
}
