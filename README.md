# Singe

This package runs SIGMA rules on event logs and supports a framework for adding new log types.

## Install

    go get github.com/Adversary-Informed-Defense/singe

## Testing

```bash
cd test
go test
```

## Example

```go
package main

import (
  "fmt"
  "log"

  "github.com/Adversary-Informed-Defense/singe"
)

func main() {
  // TODO
}
```

## Authors

* Jeffrey Wong
* Thomas Hoffman
(Based on the implementation by markuskont go-sigma-rule-engine)

## Event Log Types

Currently supported event log types with their enumerated values are:

* String: `StringType`
* JSON: `JSONType`
