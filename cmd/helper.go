// cmd/helper.go
// Helper commands for CLI.

package cmd

import (
	"errors"
	"time"
)

var ErrParamNotFound = errors.New("return parameter not found")
var ErrInvalidReturnParams = errors.New("invalid return parameters")

func getParam(params map[string]interface{}, name string) (interface{}, error) {
	paramInterface, ok := params[name]
	if !ok {
		return "", ErrParamNotFound
	}
	return paramInterface, nil
}

func getString(params map[string]interface{}, name string) (string, error) {
	paramInterface, ok := params[name]
	if !ok {
		return "", ErrParamNotFound
	}
	val, ok := paramInterface.(string)
	if !ok {
		return "", ErrInvalidReturnParams
	}
	return val, nil
}

func getSliceOfStrings(params map[string]interface{}, name string) ([]string, error) {
	paramInterface, ok := params[name]
	if !ok {
		return nil, ErrParamNotFound
	}
	sliceOfInterfaces, ok := paramInterface.([]interface{})
	if !ok {
		return nil, ErrInvalidReturnParams
	}
	slice := make([]string, len(sliceOfInterfaces))
	for i := range sliceOfInterfaces {
		slice[i], ok = sliceOfInterfaces[i].(string)
		if !ok {
			return nil, ErrInvalidReturnParams
		}
	}
	return slice, nil
}

func getDuration(params map[string]interface{}, name string) (time.Duration, error) {
	paramInterface, ok := params[name]
	if !ok {
		return time.Duration(0), ErrParamNotFound
	}
	intVal, ok := paramInterface.(int64)
	if !ok {
		return time.Duration(0), ErrInvalidReturnParams
	}
	val := time.Duration(intVal)
	return val, nil
}

func getSlice(params map[string]interface{}, name string) ([]interface{}, error) {
	paramInterface, ok := params[name]
	if !ok {
		return nil, ErrParamNotFound
	}
	sliceOfInterfaces, ok := paramInterface.([]interface{})
	if !ok {
		return nil, ErrInvalidReturnParams
	}
	return sliceOfInterfaces, nil
}
