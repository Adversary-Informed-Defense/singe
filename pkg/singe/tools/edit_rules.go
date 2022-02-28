package tools

import (
	"bytes"
	"io/ioutil"
	"strings"

	sigma "github.com/markuskont/go-sigma-rule-engine/pkg/sigma/v2"
	logrus "github.com/sirupsen/logrus"
	objx "github.com/stretchr/objx"
	yaml "gopkg.in/yaml.v2"
)

// mapToKey returns the matching key for the value arguement in the mapping
func mapToKey(valStr string, mapping objx.Map) (string, bool) {
	for key, val := range mapping {
		if val == valStr && !(strings.Contains(key, "#")) {
			return key, true
		}
	}
	return "", false
}

// mapToVal returns the matching value for the key arguement in the mapping
func mapToVal(keyStr string, mapping objx.Map) (interface{}, bool) {
	for key, val := range mapping {
		if key == keyStr && !(strings.Contains(key, "#")) {
			return val, true
		}
	}
	return nil, false
}

// editRule uses the mapping arguement to replace the field names of the Sigma rule's identifiers
func editRule(rule sigma.Rule, mapping objx.Map) sigma.Rule {
	newDetection := sigma.Detection{}
	// Iterate over each detection condition of the rule
	for key, val := range rule.Detection {
		// The "condition" field of the rule does not need to be changed
		if key == "condition" {
			newDetection[key] = val
		} else {
			switch val.(type) {
			case []interface{}:
				newDetection[key] = val
			case map[interface{}]interface{}:
				// Replace the selection field with the corresponding Winlog field path
				newSelection := make(map[interface{}]interface{})
				for selKey, selVal := range val.(map[interface{}]interface{}) {
					// Split is necessary for parsing field modifiers (contains, ends with, etc.)
					splitKey := strings.SplitN(selKey.(string), "|", 2)
					k, _ := mapToVal(splitKey[0], mapping) // Only need to check boolean value to see if edit occurred
					newKey := strings.Join(append([]string{k.(string)}, splitKey[1:]...), "|")
					newSelection[newKey] = selVal
				}
				newDetection[key] = newSelection
			default:
				logrus.Infof("Error unknown detection element type")
				panic("Error")
			}
		}
	}
	rule.Detection = newDetection
	return rule
}

// AddMappedRules edits the identifier field names of each Sigma rule in a directory and adds them to a ruleset
func AddMappedRules(ruleset *sigma.Ruleset, path string, mapping objx.Map) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		logrus.Infof("Error opening directory: %s", err)
		return err
	}
	// Wrap rule creation
	for _, fileName := range files {
		// Read in rule
		file, err := ioutil.ReadFile(path + fileName.Name())
		if err != nil {
			logrus.Infof("Error openning file: %s", err)
			continue
		}
		var rule sigma.Rule
		if err := yaml.Unmarshal(file, &rule); err != nil {
			logrus.Infof("Error unmarshalling YAML file: %s", err)
			continue
		}

		// If the rule is successfully read in, increment the number of processed rules
		ruleset.Total++

		// Map rule fields
		rule = editRule(rule, mapping)

		// Create RuleHandle struct
		ruleHandle := sigma.RuleHandle{
			Path: path + fileName.Name(),
			Rule: rule,
			Multipart: func() bool {
				return !bytes.HasPrefix(file, []byte("---")) && bytes.Contains(file, []byte("---"))
			}(),
		}
		if ruleHandle.Multipart {
			ruleset.Unsupported++
			continue
		}

		// Make Tree struct
		tree, err := sigma.NewTree(ruleHandle)
		if err != nil {
			switch err.(type) {
			case sigma.ErrUnsupportedToken, *sigma.ErrUnsupportedToken:
				ruleset.Unsupported++
			default:
				ruleset.Failed++
			}
			continue
		}

		// Append Tree to Ruleset struct
		ruleset.Rules = append(ruleset.Rules, tree)
		ruleset.Ok++
	}

	return nil
}
