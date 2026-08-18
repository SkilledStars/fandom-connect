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
	Kind  string
}

var gaqlIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]*$`)

func lexGAQL(query string) ([]gaqlToken, error) {
	if len(query) == 0 || len(query) > 128<<10 {
		return nil, errors.New("GAQL query must contain between 1 byte and 128 KB")
	}
	var tokens []gaqlToken
	for index := 0; index < len(query); {
		ch := query[index]
		if ch == '\'' || ch == '"' {
			start := index
			quote := ch
			index++
			escaped := false
			closed := false
			for index < len(query) {
				current := query[index]
				if escaped {
					escaped = false
					index++
					continue
				}
				if current == '\\' {
					escaped = true
					index++
					continue
				}
				if current == quote {
					tokens = append(tokens, gaqlToken{
						Value: query[start+1 : index],
						Start: start,
						End:   index + 1,
						Kind:  "string",
					})
					index++
					closed = true
					break
				}
				index++
			}
			if !closed {
				return nil, errors.New("GAQL contains an unterminated string")
			}
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
			tokens = append(tokens, gaqlToken{Value: query[start:index], Start: start, End: index, Kind: "identifier"})
			continue
		}
		if unicode.IsDigit(rune(ch)) || (ch == '-' && index+1 < len(query) && unicode.IsDigit(rune(query[index+1]))) {
			start := index
			index++
			for index < len(query) && unicode.IsDigit(rune(query[index])) {
				index++
			}
			if index < len(query) && query[index] == '.' {
				index++
				for index < len(query) && unicode.IsDigit(rune(query[index])) {
					index++
				}
			}
			tokens = append(tokens, gaqlToken{Value: query[start:index], Start: start, End: index, Kind: "number"})
			continue
		}
		if strings.ContainsRune("(),=<>!", rune(ch)) {
			start := index
			index++
			if index < len(query) && strings.ContainsRune("=", rune(query[index])) && strings.ContainsRune("!<>", rune(ch)) {
				index++
			}
			tokens = append(tokens, gaqlToken{Value: query[start:index], Start: start, End: index, Kind: "symbol"})
			continue
		}
		if unicode.IsSpace(rune(ch)) {
			index++
			continue
		}
		return nil, fmt.Errorf("GAQL contains unsupported character %q", ch)
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
		if token.Kind == "identifier" && strings.EqualFold(token.Value, "FROM") {
			fromCount++
			if index+1 >= len(tokens) || tokens[index+1].Kind != "identifier" || !gaqlIdentifier.MatchString(tokens[index+1].Value) {
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

// explicitCampaignIDs extracts the positive campaign boundary already present
// in a Google Ads query. It never changes the query. Google's documented GAQL
// grammar permits WHERE conditions joined only by AND, so a positive equality
// or IN condition cannot be weakened by another valid condition.
func explicitCampaignIDs(query string) ([]string, error) {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return nil, err
	}
	whereAt, whereCount := -1, 0
	endAt := len(tokens)
	for index, token := range tokens {
		if token.Kind != "identifier" {
			continue
		}
		upper := strings.ToUpper(token.Value)
		if upper == "WHERE" {
			whereAt = index
			whereCount++
			continue
		}
		if whereAt >= 0 && (upper == "ORDER" || upper == "LIMIT" || upper == "PARAMETERS") {
			endAt = index
			break
		}
	}
	if whereCount != 1 || whereAt < 0 || whereAt+1 >= endAt {
		return nil, errors.New("campaign-scoped GAQL must contain exactly one WHERE clause")
	}

	var ids []string
	seenCampaignField := false
	for index := whereAt + 1; index < endAt; index++ {
		token := tokens[index]
		if token.Kind == "identifier" && strings.EqualFold(token.Value, "OR") {
			return nil, errors.New("GAQL OR conditions are not accepted")
		}
		if token.Kind == "identifier" && strings.EqualFold(token.Value, "NOT") {
			return nil, errors.New("GAQL NOT conditions are not accepted")
		}
		if token.Kind != "identifier" || !strings.EqualFold(token.Value, "campaign.id") {
			continue
		}
		seenCampaignField = true
		if index+2 >= endAt {
			return nil, errors.New("campaign.id filter is incomplete")
		}
		operator := strings.ToUpper(tokens[index+1].Value)
		switch operator {
		case "=":
			id := tokens[index+2].Value
			if tokens[index+2].Kind != "number" || !isNonzeroPositiveID(id) {
				return nil, errors.New("campaign.id equality must use a numeric campaign ID")
			}
			ids = append(ids, id)
			index += 2
		case "IN":
			if tokens[index+2].Value != "(" {
				return nil, errors.New("campaign.id IN must contain a numeric ID list")
			}
			cursor := index + 3
			expectID := true
			foundID := false
			for ; cursor < endAt; cursor++ {
				current := tokens[cursor]
				if current.Value == ")" {
					if expectID || !foundID {
						return nil, errors.New("campaign.id IN must contain at least one numeric campaign ID")
					}
					break
				}
				if expectID {
					if current.Kind != "number" || !isNonzeroPositiveID(current.Value) {
						return nil, errors.New("campaign.id IN contains a non-numeric campaign ID")
					}
					ids = append(ids, current.Value)
					foundID = true
					expectID = false
					continue
				}
				if current.Value != "," {
					return nil, errors.New("campaign.id IN contains an invalid separator")
				}
				expectID = true
			}
			if cursor >= endAt || tokens[cursor].Value != ")" {
				return nil, errors.New("campaign.id IN list is not closed")
			}
			index = cursor
		default:
			return nil, errors.New("campaign.id must be restricted with = or IN")
		}
	}
	if !seenCampaignField || len(ids) == 0 {
		return nil, errors.New("query does not contain an explicit campaign.id = or campaign.id IN boundary")
	}
	return uniqueStrings(ids), nil
}

func selectedFields(query string) ([]string, error) {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return nil, err
	}
	selectAt, fromAt := -1, -1
	for index, token := range tokens {
		if token.Kind != "identifier" {
			continue
		}
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
		if token.Kind == "identifier" && strings.Contains(token.Value, ".") {
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
		if token.Kind == "identifier" && strings.Contains(token.Value, ".") {
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

func rejectGAQLDisjunction(query string) error {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return err
	}
	for _, token := range tokens {
		if token.Kind != "identifier" {
			continue
		}
		if strings.EqualFold(token.Value, "OR") {
			return errors.New("GAQL OR conditions are not accepted")
		}
		if strings.EqualFold(token.Value, "NOT") {
			return errors.New("GAQL NOT conditions are not accepted")
		}
	}
	return nil
}

// gaqlWhereReferencesField reports whether a field is present in the WHERE
// clause. It is used to distinguish an unscoped query (which the gateway can
// safely narrow) from a caller-supplied campaign boundary that is malformed or
// uses an unsupported operator (which must be rejected).
func gaqlWhereReferencesField(query, field string) (bool, error) {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return false, err
	}
	whereAt := -1
	endAt := len(tokens)
	for index, token := range tokens {
		if token.Kind != "identifier" {
			continue
		}
		upper := strings.ToUpper(token.Value)
		if upper == "WHERE" {
			if whereAt >= 0 {
				return false, errors.New("GAQL must not contain multiple WHERE clauses")
			}
			whereAt = index
			continue
		}
		if whereAt >= 0 && (upper == "ORDER" || upper == "LIMIT" || upper == "PARAMETERS") {
			endAt = index
			break
		}
	}
	if whereAt < 0 {
		return false, nil
	}
	for _, token := range tokens[whereAt+1 : endAt] {
		if token.Kind == "identifier" && strings.EqualFold(token.Value, field) {
			return true, nil
		}
	}
	return false, nil
}

// addGAQLCondition narrows a valid query with one additional AND condition.
// The condition is generated exclusively by the gateway; caller input is
// never interpolated into it. GAQL only permits AND at the top level, and OR
// and NOT are rejected before this function is called, so the new condition
// cannot be weakened by the original query.
func addGAQLCondition(query, condition string) (string, error) {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return "", err
	}
	whereCount := 0
	insertAt := -1
	for _, token := range tokens {
		if token.Kind != "identifier" {
			continue
		}
		upper := strings.ToUpper(token.Value)
		if upper == "WHERE" {
			whereCount++
			continue
		}
		if upper == "ORDER" || upper == "LIMIT" || upper == "PARAMETERS" {
			insertAt = token.Start
			break
		}
	}
	if whereCount > 1 {
		return "", errors.New("GAQL must not contain multiple WHERE clauses")
	}
	if insertAt < 0 {
		insertAt = len(query)
	}
	prefixEnd := insertAt
	for prefixEnd > 0 && unicode.IsSpace(rune(query[prefixEnd-1])) {
		prefixEnd--
	}
	connector := " WHERE "
	if whereCount == 1 {
		connector = " AND "
	}
	rewritten := query[:prefixEnd] + connector + condition
	if insertAt < len(query) {
		rewritten += " " + query[insertAt:]
	}
	if len(rewritten) > 128<<10 {
		return "", errors.New("campaign grant is too large for one GAQL query; use full account access")
	}
	return rewritten, nil
}

// ensureGAQLSelectedField adds a non-sensitive authorization field to SELECT
// when the caller omitted it. Fandom ignores additional Google response fields,
// while the gateway needs the canonical resource name to authorize every row.
func ensureGAQLSelectedField(query, field string) (string, error) {
	fields, err := selectedFields(query)
	if err != nil {
		return "", err
	}
	for _, selected := range fields {
		if strings.EqualFold(selected, field) {
			return query, nil
		}
	}
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return "", err
	}
	fromAt := -1
	for _, token := range tokens {
		if token.Kind == "identifier" && strings.EqualFold(token.Value, "FROM") {
			fromAt = token.Start
			break
		}
	}
	if fromAt < 0 {
		return "", errors.New("GAQL SELECT clause is malformed")
	}
	prefixEnd := fromAt
	for prefixEnd > 0 && unicode.IsSpace(rune(query[prefixEnd-1])) {
		prefixEnd--
	}
	rewritten := query[:prefixEnd] + ", " + field + " " + query[fromAt:]
	if len(rewritten) > 128<<10 {
		return "", errors.New("GAQL query exceeds the 128 KB safety limit")
	}
	return rewritten, nil
}

func gaqlWhereTokenRange(tokens []gaqlToken) (int, int, error) {
	whereAt := -1
	endAt := len(tokens)
	for index, token := range tokens {
		if token.Kind != "identifier" {
			continue
		}
		upper := strings.ToUpper(token.Value)
		if upper == "WHERE" {
			if whereAt >= 0 {
				return 0, 0, errors.New("GAQL must not contain multiple WHERE clauses")
			}
			whereAt = index
			continue
		}
		if whereAt >= 0 && (upper == "ORDER" || upper == "LIMIT" || upper == "PARAMETERS") {
			endAt = index
			break
		}
	}
	if whereAt < 0 {
		return 0, 0, errors.New("GAQL query must contain a WHERE clause")
	}
	return whereAt + 1, endAt, nil
}

func exactGAQLStringFilterValues(query, field string) ([]string, error) {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return nil, err
	}
	start, end, err := gaqlWhereTokenRange(tokens)
	if err != nil {
		return nil, err
	}
	var values []string
	for index := start; index < end; index++ {
		if tokens[index].Kind != "identifier" || !strings.EqualFold(tokens[index].Value, field) {
			continue
		}
		if index+2 >= end {
			return nil, fmt.Errorf("%s filter is incomplete", field)
		}
		operator := tokens[index+1]
		switch {
		case operator.Kind == "symbol" && operator.Value == "=":
			if tokens[index+2].Kind != "string" {
				return nil, fmt.Errorf("%s equality must use a quoted string", field)
			}
			value, decodeErr := decodeGAQLString(tokens[index+2].Value)
			if decodeErr != nil {
				return nil, fmt.Errorf("%s equality: %w", field, decodeErr)
			}
			values = append(values, value)
		case operator.Kind == "identifier" && strings.EqualFold(operator.Value, "IN"):
			if tokens[index+2].Value != "(" {
				return nil, fmt.Errorf("%s IN filter must contain a quoted string list", field)
			}
			cursor := index + 3
			expectValue := true
			foundValue := false
			for ; cursor < end; cursor++ {
				current := tokens[cursor]
				if current.Value == ")" {
					if expectValue || !foundValue {
						return nil, fmt.Errorf("%s IN filter must contain at least one quoted string", field)
					}
					break
				}
				if expectValue {
					if current.Kind != "string" {
						return nil, fmt.Errorf("%s IN filter contains a non-string value", field)
					}
					value, decodeErr := decodeGAQLString(current.Value)
					if decodeErr != nil {
						return nil, fmt.Errorf("%s IN filter: %w", field, decodeErr)
					}
					values = append(values, value)
					foundValue = true
					expectValue = false
					continue
				}
				if current.Value != "," {
					return nil, fmt.Errorf("%s IN filter contains an invalid separator", field)
				}
				expectValue = true
			}
			if cursor >= end || tokens[cursor].Value != ")" {
				return nil, fmt.Errorf("%s IN filter is not closed", field)
			}
			index = cursor
		}
	}
	return uniqueStrings(values), nil
}

func exactGAQLNumericFilterValues(query, field string) ([]string, error) {
	_, tokens, err := gaqlResource(query)
	if err != nil {
		return nil, err
	}
	start, end, err := gaqlWhereTokenRange(tokens)
	if err != nil {
		return nil, err
	}
	var values []string
	for index := start; index < end; index++ {
		if tokens[index].Kind != "identifier" || !strings.EqualFold(tokens[index].Value, field) {
			continue
		}
		if index+2 >= end {
			return nil, fmt.Errorf("%s filter is incomplete", field)
		}
		operator := tokens[index+1]
		switch {
		case operator.Kind == "symbol" && operator.Value == "=":
			if tokens[index+2].Kind != "number" || !isNonzeroPositiveID(tokens[index+2].Value) {
				return nil, fmt.Errorf("%s equality must use a positive numeric ID", field)
			}
			values = append(values, tokens[index+2].Value)
		case operator.Kind == "identifier" && strings.EqualFold(operator.Value, "IN"):
			if tokens[index+2].Value != "(" {
				return nil, fmt.Errorf("%s IN filter must contain a numeric ID list", field)
			}
			cursor := index + 3
			expectValue := true
			foundValue := false
			for ; cursor < end; cursor++ {
				current := tokens[cursor]
				if current.Value == ")" {
					if expectValue || !foundValue {
						return nil, fmt.Errorf("%s IN filter must contain at least one numeric ID", field)
					}
					break
				}
				if expectValue {
					if current.Kind != "number" || !isNonzeroPositiveID(current.Value) {
						return nil, fmt.Errorf("%s IN filter contains a non-numeric ID", field)
					}
					values = append(values, current.Value)
					foundValue = true
					expectValue = false
					continue
				}
				if current.Value != "," {
					return nil, fmt.Errorf("%s IN filter contains an invalid separator", field)
				}
				expectValue = true
			}
			if cursor >= end || tokens[cursor].Value != ")" {
				return nil, fmt.Errorf("%s IN filter is not closed", field)
			}
			index = cursor
		}
	}
	return uniqueStrings(values), nil
}

func decodeGAQLString(value string) (string, error) {
	var decoded strings.Builder
	decoded.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			decoded.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) {
			return "", errors.New("quoted string ends with an incomplete escape")
		}
		index++
		switch value[index] {
		case '\\', '\'', '"':
			decoded.WriteByte(value[index])
		default:
			return "", fmt.Errorf("quoted string contains unsupported escape \\%c", value[index])
		}
	}
	return decoded.String(), nil
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
