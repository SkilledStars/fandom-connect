package gateway

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

type gaqlToken struct {
	Value string
	Start int
	End   int
}

var gaqlIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]*$`)

func lexGAQL(query string) ([]gaqlToken, error) {
	if len(query) == 0 || len(query) > 128<<10 {
		return nil, errors.New("GAQL query must contain between 1 byte and 128 KB")
	}
	var tokens []gaqlToken
	inString := false
	escaped := false
	for index := 0; index < len(query); {
		ch := query[index]
		if inString {
			if escaped {
				escaped = false
				index++
				continue
			}
			if ch == '\\' {
				escaped = true
				index++
				continue
			}
			if ch == '\'' {
				inString = false
			}
			index++
			continue
		}
		if ch == '\'' {
			inString = true
			index++
			continue
		}
		if ch == ';' {
			return nil, errors.New("GAQL semicolons are not accepted")
		}
		if index+1 < len(query) && (query[index:index+2] == "--" || query[index:index+2] == "/*" || query[index:index+2] == "*/") {
			return nil, errors.New("GAQL comments are not accepted")
		}
		if unicode.IsLetter(rune(ch)) || ch == '_' {
			start := index
			index++
			for index < len(query) {
				r := rune(query[index])
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) && query[index] != '_' && query[index] != '.' {
					break
				}
				index++
			}
			tokens = append(tokens, gaqlToken{Value: query[start:index], Start: start, End: index})
			continue
		}
		index++
	}
	if inString {
		return nil, errors.New("GAQL contains an unterminated string")
	}
	return tokens, nil
}

func gaqlResource(query string) (string, []gaqlToken, error) {
	tokens, err := lexGAQL(query)
	if err != nil {
		return "", nil, err
	}
	resource := ""
	fromCount := 0
	for index, token := range tokens {
		if strings.EqualFold(token.Value, "FROM") {
			fromCount++
			if index+1 >= len(tokens) || !gaqlIdentifier.MatchString(tokens[index+1].Value) {
				return "", nil, errors.New("GAQL FROM clause is malformed")
			}
			resource = strings.ToLower(tokens[index+1].Value)
		}
	}
	if fromCount != 1 {
		return "", nil, errors.New("GAQL must contain exactly one FROM clause")
	}
	return resource, tokens, nil
}

func rewriteGAQL(query, condition string) (string, error) {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return "", err
	}
	fromIndex := -1
	whereIndex := -1
	suffixIndex := len(query)
	for index, token := range tokens {
		upper := strings.ToUpper(token.Value)
		if upper == "FROM" {
			fromIndex = index
			continue
		}
		if fromIndex < 0 || index <= fromIndex {
			continue
		}
		if upper == "WHERE" && whereIndex < 0 {
			whereIndex = index
		}
		if upper == "ORDER" || upper == "LIMIT" || upper == "PARAMETERS" {
			suffixIndex = token.Start
			break
		}
	}
	if fromIndex < 0 {
		return "", errors.New("GAQL FROM clause is missing")
	}
	prefix := strings.TrimRightFunc(query[:suffixIndex], unicode.IsSpace)
	suffix := query[suffixIndex:]
	if whereIndex >= 0 {
		return prefix + " AND (" + condition + ") " + suffix, nil
	}
	return prefix + " WHERE " + condition + " " + suffix, nil
}

func selectedFields(query string) ([]string, error) {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return nil, err
	}
	selectAt, fromAt := -1, -1
	for index, token := range tokens {
		if strings.EqualFold(token.Value, "SELECT") && selectAt < 0 {
			selectAt = index
		}
		if strings.EqualFold(token.Value, "FROM") {
			fromAt = index
			break
		}
	}
	if selectAt < 0 || fromAt <= selectAt {
		return nil, errors.New("GAQL SELECT clause is malformed")
	}
	seen := map[string]bool{}
	for _, token := range tokens[selectAt+1 : fromAt] {
		if strings.Contains(token.Value, ".") {
			seen[strings.ToLower(token.Value)] = true
		}
	}
	fields := make([]string, 0, len(seen))
	for field := range seen {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields, nil
}

func referencedFields(query string) ([]string, error) {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, token := range tokens {
		if strings.Contains(token.Value, ".") {
			seen[strings.ToLower(token.Value)] = true
		}
	}
	fields := make([]string, 0, len(seen))
	for field := range seen {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields, nil
}

func numericInCondition(field string, values []string) string {
	if len(values) == 0 {
		return field + " = 0"
	}
	return fmt.Sprintf("%s IN (%s)", field, strings.Join(values, ", "))
}

func stringInCondition(field string, values []string) string {
	if len(values) == 0 {
		return field + " = '__fandom_gateway_no_match__'"
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		if strings.ContainsAny(value, "'\\\r\n") {
			continue
		}
		quoted = append(quoted, "'"+value+"'")
	}
	if len(quoted) == 0 {
		return field + " = '__fandom_gateway_no_match__'"
	}
	return fmt.Sprintf("%s IN (%s)", field, strings.Join(quoted, ", "))
}
