package httpx

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strconv"
	"testing"
	"unicode"
)

// errorMessage is one WriteError message literal and where it sits.
type errorMessage struct {
	pos  token.Pos
	text string
}

// A mechanical "an error string is not capitalised" pass, which is the Go
// convention for errors.New and not for a message the customer reads, moved the
// first letter of several acronyms into the middle of the word: WriteError
// answered "dNS zone could not be updated" and "pHP version change failed".
// These strings are the API error field, so the broken word is exactly what the
// screen shows at the moment the panel refuses an action, and no locale file
// stands between the constant and the customer.
func TestNoErrorMessageStartsWithABrokenAcronym(t *testing.T) {
	var broken []string
	forEachInternalFile(t, func(parsed *ast.File, rel string, at func(token.Pos) int) {
		for _, message := range brokenErrorMessages(parsed) {
			broken = append(broken, fmt.Sprintf("%s:%d %q", rel, at(message.pos), message.text))
		}
	})
	sort.Strings(broken)
	for _, site := range broken {
		t.Errorf("%s starts with a lowercased acronym; write the acronym in capitals", site)
	}
}

// brokenErrorMessages returns every WriteError message literal that opens with a
// lowercase letter followed by a capital.
func brokenErrorMessages(file *ast.File) []errorMessage {
	var found []errorMessage
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if message, ok := writeErrorMessage(call); ok && startsWithBrokenAcronym(message.text) {
			found = append(found, message)
		}
		return true
	})
	return found
}

// writeErrorMessage returns the trailing string literal of a WriteError call.
func writeErrorMessage(call *ast.CallExpr) (errorMessage, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "WriteError" || len(call.Args) == 0 {
		return errorMessage{}, false
	}
	literal, ok := call.Args[len(call.Args)-1].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return errorMessage{}, false
	}
	text, err := strconv.Unquote(literal.Value)
	if err != nil {
		return errorMessage{}, false
	}
	return errorMessage{pos: literal.Pos(), text: text}, true
}

func startsWithBrokenAcronym(message string) bool {
	runes := []rune(message)
	return len(runes) > 1 && unicode.IsLower(runes[0]) && unicode.IsUpper(runes[1])
}
