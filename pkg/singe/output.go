package singe

import (
	sigma "github.com/markuskont/go-sigma-rule-engine/pkg/sigma/v2"
)

type RuleData struct {
	ID    string   `json:"id"`
	Title string   `json:"name"`
	Tags  []string `json:"tags"`
}

type Rule struct {
	RuleData `json:"rule"`
}

type EngineResult struct {
	MatchList []Rule   `json:"matches"`
	TagList   []string `json:"tags"`
	IDList    []string `json:"ids"`
	Count     int      `json:"count"`
}

type OutputMessage struct {
	Event  sigma.Event  `json:"event"`
	Result EngineResult `json:"sigma"`
}
