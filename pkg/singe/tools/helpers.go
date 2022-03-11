package tools

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	sigma "github.com/markuskont/go-sigma-rule-engine/pkg/sigma/v2"
	logrus "github.com/sirupsen/logrus"
	objx "github.com/stretchr/objx"
)

// IsJSON checks if a string is a valid JSON format
func IsJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}

// LoadJSONFile reads and returns a JSON file as an objx.Map struct from the file path
func LoadJSONFile(f string) (output objx.Map) {
	jsonFile, err := os.Open(f)
	if err != nil {
		// Handle error loading JSON file
		logrus.Infof("Error openning JSON file: %s", err)
	}
	defer jsonFile.Close()
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		// Handle error reading JSON file
		logrus.Infof("Error reading JSON file: %s", err)
	}
	return objx.MustFromJSON(string(byteValue))
}

// GetDirectory returns a string of the calling goroutine's directory
func GetDirectory() string {
	_, filename, _, _ := runtime.Caller(1)
	filenameSlice := strings.Split(filename, "/")
	filenameSlice[len(filenameSlice)-1] = ""
	dirName := strings.Join(filenameSlice[:len(filenameSlice)-1], "/") + "/"
	return dirName
}

// Contains checks whether a string slice contains a particular string
func Contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// GetMapKeys returns a slice containing the keys of a map
func GetMapKeys(m map[string]interface{}) []string {
	keys := make([]string, len(m))
	i := 0
	for key := range m {
		keys[i] = key
		i++
	}
	return keys
}

// GetListEnvVar converts an environment variable to a slice of strings
func GetListEnvVar(name string) []string {
	var envVar []string = strings.Split(os.Getenv(name), "\n")
	return envVar[:len(envVar)-1]
}

// ErrorHandler handles errors during goroutines
func ErrorHandler(e chan error) {
	for err := range e {
		// TODO: Implement appropriate error handling
		// Log errors to terminal
		logrus.Infof("Error: %s", err)
	}
}

// DeleteRules removes rule files defined by user in DELETE_RULESETS
func DeleteRules() {
	omitRuleSets := GetListEnvVar("DELETE_RULESETS")
	if omitRuleSets != nil {
		logrus.Infof("Removing rule sets: %s", omitRuleSets)
	}
	for _, omitRuleSet := range omitRuleSets {
		os.RemoveAll(omitRuleSet)
	}
}

// LoadRules creates a Sigma ruleset containing the rules from the directory path
func LoadRules(path string) *sigma.Ruleset {
	ruleset, err := sigma.NewRuleset(sigma.Config{
		Directory: []string{path},
	})
	if err != nil {
		logrus.Errorf("Failed to load sigma rules: %s", err)
	}
	logrus.Infof(
		"Found %d files, %d ok, %d failed, %d unsupported",
		ruleset.Total,
		ruleset.Ok,
		ruleset.Failed,
		ruleset.Unsupported,
	)
	return ruleset
}

// RemoveStringDuplicates returns the string array argument with all duplicate values removed
func RemoveStringDuplicates(arr []string) []string {
	keys := make(map[string]bool)
	var output []string
	for _, elem := range arr {
		if _, val := keys[elem]; !val {
			keys[elem] = true
			output = append(output, elem)
		}
	}
	return output
}
