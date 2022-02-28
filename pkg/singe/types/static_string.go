package types

type StaticString struct {
	Message string
}

func (s StaticString) Keywords() ([]string, bool) {
	return []string{string(s.Message)}, true
}

func (s StaticString) Select(key string) (interface{}, bool) {
	return nil, false
}
