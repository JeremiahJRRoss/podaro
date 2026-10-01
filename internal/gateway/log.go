// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"encoding/json"
	"io"
	"log"
)

type logLogger = log.Logger

func newLogger(w io.Writer) *log.Logger { return log.New(w, "", 0) }

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
