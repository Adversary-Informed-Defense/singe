package singe

import (
	"encoding/json"

	sigma "github.com/markuskont/go-sigma-rule-engine/pkg/sigma/v2"
	objx "github.com/stretchr/objx"

	tools "github.com/Adversary-Informed-Defense/singe/pkg/singe/tools"
	types "github.com/Adversary-Informed-Defense/singe/pkg/singe/types"
)

// Load embedded vendor to log type mapping
var vendorMapping objx.Map

func init() {
	mapping, err := objx.FromJSON(vendorMapStr)
	if err != nil {
		panic(err)
	}
	vendorMapping = mapping
}

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

// CreateEngine returns a SigmaEngine struct instance with the ruleset defined by the Sigma rules in the directory at the path argument
func CreateEngine(path string) SigmaEngine {
	ruleset := tools.LoadRules(path)
	return SigmaEngine{ruleset}
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
	if results, matched := s.ruleset.EvalAll(event); matched {
		outputResult := EngineResult{
			Count: len(results),
		}
		var allTags []string
		var allIDs []string

		// Parse Sigma rule match data
		for _, res := range results {
			allTags = append(allTags, res.Tags...)
			allIDs = append(allIDs, res.ID)

			rule := Rule{
				RuleData{
					ID:    res.ID,
					Title: res.Title,
					Tags:  res.Tags,
				},
			}
			outputResult.MatchList = append(outputResult.MatchList, rule)
		}

		// Remove repeated tags
		outputResult.TagList = tools.RemoveStringDuplicates(allTags)

		// Should not be possible to see duplicate IDs
		outputResult.IDList = allIDs

		output, err := json.Marshal(OutputMessage{event, outputResult})
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
