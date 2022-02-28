package singe

import (
	"encoding/json"

	sigma "github.com/markuskont/go-sigma-rule-engine/pkg/sigma/v2"
	objx "github.com/stretchr/objx"

	tools "github.com/Adversary-Informed-Defense/singe/pkg/singe/tools"
	types "github.com/Adversary-Informed-Defense/singe/pkg/singe/types"
)

// Load embedded vendor to log type mapping
var vendorMapping, _ = objx.FromJSON(vendorMapStr)

// LogType represents the enumerated event log types
type LogType int64

const (
	StringType LogType = iota
	JSONType
)

func (l LogType) String() string {
	switch l {
	case StringType:
		return "string"
	case JSONType:
		return "json"
	}
	return "Unreachable: unknown type"
}

func toLogType(str string) LogType {
	switch str {
	case "StringType":
		return StringType
	case "JSONType":
		return JSONType
	default:
		return StringType
	}
}

type SigmaEngine struct {
	ruleset *sigma.Ruleset
}

func CreateEngine(path string) SigmaEngine {
	ruleset := tools.LoadRules(path)
	return SigmaEngine{ruleset}
}

type OutputMessage struct {
	Event  sigma.Event
	Result sigma.Results
}

// Match evaluates a log message against a Sigma ruleset, returning whether at least one match occurred and the list of matching rules, if any
func (s SigmaEngine) Match(msg string, vendor string) ([]byte, bool, error) {
	// Map vendor string to LogType
	lType := mapVendor(vendor)
	// Cast log file to appropriate Sigma Event type
	event, err := castEvent(msg, lType)
	if err != nil {
		return nil, false, err
	}
	// Match event against Sigma rules
	if res, matched := s.ruleset.EvalAll(event); matched {
		// Handle match
		output, err := json.Marshal(OutputMessage{event, res})
		if err != nil {
			return nil, false, err
		}
		return output, true, nil
	}
	return nil, false, nil
}

// mapVendor returns the enumerated log type mapped from the vendor string
func mapVendor(vendor string) LogType {
	strType := vendorMapping.Get(vendor)
	if strType.IsNil() {
		return StringType
	}
	lType := toLogType(strType.String())

	return lType
}

// castEvent returns a Sigma Event representation of a string of type logType
func castEvent(msg string, lType LogType) (sigma.Event, error) {
	switch lType {
	case StringType:
		return types.StaticString{Message: msg}, nil
	case JSONType:
		event := sigma.DynamicMap{}
		if err := json.Unmarshal([]byte(msg), &event); err != nil {
			return nil, err
		}
		return sigma.Event(event), nil
	default:
		if tools.IsJSON(msg) {
			event := sigma.DynamicMap{}
			// TODO: Error check is unnecessary; if IsJSON() returns true, error will never occur
			if err := json.Unmarshal([]byte(msg), &event); err != nil {
				return nil, err
			}
			return sigma.Event(event), nil
		} else {
			return types.StaticString{Message: msg}, nil
		}
	}
}
