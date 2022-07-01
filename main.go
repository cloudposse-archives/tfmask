package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

type match struct {
	leadingWhitespace  string
	property           string // something like `stage.0.action.0.configuration.OAuthToken`
	trailingWhitespace string
	firstQuote         string // < or "
	oldValue           string
	secondQuote        string // > or "
	thirdQuote         string // < or " or (
	newValue           string
	fourthQuote        string // > or " or )
	postfix            string
}

type keyValueMatch struct {
	leadingWhitespace       string
	property                string
	assignmentOperator      string
	trailingWhitespaceAfter string
	oldValue                string
}

type expression struct {
	planStatusRegex         *regexp.Regexp
	reTfPlanLine            *regexp.Regexp
	reTfPlanCurrentResource *regexp.Regexp
	reMapKeyPair            *regexp.Regexp
	reJSON                  *regexp.Regexp
	resourceIndex           int
	assign                  string
	operator                string
}

func init() {
	// make sure we only have one process and that it runs on the main thread
	// (so that ideally, when we Exec, we keep our user switches and stuff)
	runtime.GOMAXPROCS(1)
	runtime.LockOSThread()
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

var versionedExpressions = map[string]expression{
	"0.11": {
		planStatusRegex: regexp.MustCompile(
			"^(.*?): (.*?) +\\(ID: (.*?)\\)$",
		),
		reTfPlanLine: regexp.MustCompile(
			`^( +)([a-zA-Z0-9%._-]+):( +)(["<])(.*?)([>"]) +=> +(["<])(.*)([>"])(.*)$`,
		),
		reTfPlanCurrentResource: regexp.MustCompile(
			"^([~/+-]+) (.*?) +(.*)$",
		),
		reMapKeyPair: regexp.MustCompile(
			"(?i)^(\\s+(?:[~+-] )?)(.*)(\\s?[=:])(\\s+)\"(.*)\"$",
		),
		reJSON: regexp.MustCompile( // TODO
			`(?i)^(\s+(?:[~+-] )?)"?(.*)"?(\s+)=(\s+)"(.*)"$`,
		),
		resourceIndex: 2,
		assign:        ":",
		operator:      "=>",
	},
	"0.12": {
		planStatusRegex: regexp.MustCompile(
			"^(.*?): (.*?) +\\[id=(.*?)\\]$",
		),
		reTfPlanLine: regexp.MustCompile(
			"^( +)([ ~a-zA-Z0-9%._-]+)=( +)([\"<])(.*?)([>\"]) +-> +(\\()(.*)(\\))(.*)$",
		),
		reTfPlanCurrentResource: regexp.MustCompile(
			"^([~/+-]+) (.*?) +(.*) (.*) (.*)$",
		),
		reMapKeyPair: regexp.MustCompile(
			`(?i)^(\s+(?:[~+-] )?)(.*)(\s=)(\s+)"(.*)"$`,
		),
		reJSON: regexp.MustCompile(
			`(?i)^(\s+(?:[~+-] )?)"?(.*?)"?(\s+)=(\s+)"(.+?)"(\s+->\s+"(.+)")?\s*$`,
		),
		resourceIndex: 3,
		assign:        "=",
		operator:      "->",
	},
}

func main() {
	log.SetFlags(0) // no timestamps on our logs

	// Character used to mask sensitive output
	var tfmaskChar = getEnv("TFMASK_CHAR", "*")
	// Pattern representing sensitive output
	var tfmaskValuesRegex = getEnv("TFMASK_VALUES_REGEX",
		"(?i)^.*[^a-zA-Z](oauth|secret|token|password|key|result|id).*$")
	// Pattern representing sensitive resource
	var tfmaskResourceRegex = getEnv("TFMASK_RESOURCES_REGEX",
		"(?i)^(random_id|random_string).*$")

	// Default to tf 0.12, but users can override
	var tfenv = getEnv("TFENV", "0.12")

	reTfValues := regexp.MustCompile(tfmaskValuesRegex)
	reTfResource := regexp.MustCompile(tfmaskResourceRegex)
	scanner := bufio.NewScanner(os.Stdin)
	versionedExpressions := versionedExpressions[tfenv]
	// initialize currentResource once before scanning
	currentResource := ""
	for scanner.Scan() {
		line := scanner.Text()
		currentResource = getCurrentResource(versionedExpressions,
			currentResource, line)
		fmt.Println(processLine(versionedExpressions, reTfResource, reTfValues,
			tfmaskChar, currentResource, line))
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func getCurrentResource(expression expression, currentResource, line string) string {
	reTfApplyCurrentResource := regexp.MustCompile("^([a-z].*?): (.*?)$")
	if expression.reTfPlanCurrentResource.MatchString(line) {
		match := expression.reTfPlanCurrentResource.FindStringSubmatch(line)
		// for tf 0.12 the resource is wrapped in quotes, so remove them
		strippedResource := strings.Replace(match[expression.resourceIndex],
			"\"", "", -1)
		currentResource = strippedResource
	} else if reTfApplyCurrentResource.MatchString(line) {
		match := reTfApplyCurrentResource.FindStringSubmatch(line)
		currentResource = match[1]
	}

	return currentResource
}

func stripAnsi(str string) string {
	const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	re := regexp.MustCompile(ansi)
	return re.ReplaceAllString(str, "")
}

func difference(a, b []string) (diff []string) {
	for i, v := range a {
		if v != b[i] {
			diff = append(diff, v)
		}
	}
	return diff
}

func processLine(expression expression, reTfResource,
	reTfValues *regexp.Regexp, tfmaskChar, currentResource,
	line string) string {
	var knownSecrets = []string{}

	originalLine := line
	// remove ansi codes
	line = stripAnsi(line)
	// process without ansi codes
	if expression.planStatusRegex.MatchString(line) {
		line = planStatus(expression.planStatusRegex, reTfResource, tfmaskChar,
			line)
	} else if expression.reTfPlanLine.MatchString(line) {
		secrets := planLine(expression.reTfPlanLine, reTfResource, reTfValues,
			currentResource, line)
		knownSecrets = append(knownSecrets, secrets...)
	} else if expression.reMapKeyPair.MatchString(line) {
		line = assignmentLine(expression.reMapKeyPair, reTfValues,
			tfmaskChar, line)
	} else if expression.reJSON.MatchString(line) {
		secrets := assignmentJSON(expression.reJSON, reTfValues, tfmaskChar, line)
		knownSecrets = append(knownSecrets, secrets...)
	}
	// compare original line with processed
	if strings.Compare(stripAnsi(originalLine), line) == 0 {
		// there were no secrets - return original line with ansi codes
		line = originalLine
	} else {
		// find difference between original line(without ansi codes) and processed line(with masked secret)
		diff := difference(strings.Split(stripAnsi(originalLine), ""), strings.Split(line, ""))
		// this difference is a secret value
		secret := strings.Join(diff, "")
		// replace secret value in original line (with ansi codes) with asterisk
		line = strings.Replace(originalLine, secret, strings.Repeat("*", len(secret)), 1)

	}

	for _, secret := range knownSecrets {
		line = strings.Replace(line, secret, maskValue(secret, tfmaskChar), -1)
	}
	// return line with ansi codes
	return line
}

func planStatus(planStatusRegex, reTfResource *regexp.Regexp, tfmaskChar,
	line string) string {
	match := planStatusRegex.FindStringSubmatch(line)
	resource := match[1]
	id := match[3]
	if reTfResource.MatchString(resource) {
		line = strings.Replace(line, id, strings.Repeat(tfmaskChar,
			utf8.RuneCountInString(id)), 1)
	}
	return line
}

func matchFromLine(reTfPlanLine *regexp.Regexp, line string) genericMatch {
	subMatch := reTfPlanLine.FindStringSubmatch(line)
	return genericMatch{
		property: subMatch[2], // something like `stage.0.action.0.configuration.OAuthToken`
		secrets:  []string{subMatch[5], subMatch[8]},
	}
}

func matchFromAssignment(reMapKeyPair *regexp.Regexp, line string) keyValueMatch {
	subMatch := reMapKeyPair.FindStringSubmatch(line)
	return keyValueMatch{
		leadingWhitespace:       subMatch[1],
		property:                subMatch[2],
		assignmentOperator:      subMatch[3],
		trailingWhitespaceAfter: subMatch[4],
		oldValue:                subMatch[5],
	}
}

func matchFromJSON(reg *regexp.Regexp, line string) genericMatch {
	subMatch := reg.FindStringSubmatch(line)

	secrets := []string{}
	if len(subMatch) > 5 {
		secrets = append(secrets, subMatch[7])
	}
	secrets = append(secrets, subMatch[5])

	return genericMatch{
		property: subMatch[2],
		secrets:  secrets,
	}
}

func planLine(reTfPlanLine, reTfResource, reTfValues *regexp.Regexp,
	currentResource, line string) []string {
	match := matchFromLine(reTfPlanLine, line)
	if reTfValues.MatchString(match.property) || reTfResource.MatchString(currentResource) {
		return match.secrets
	}
	return []string{}
}

func assignmentLine(reMapKeyPair, reTfValues *regexp.Regexp, tfmaskChar, line string) string {
	match := matchFromAssignment(reMapKeyPair, line)
	if reTfValues.MatchString(match.property) {
		maskedValue := maskValue(match.oldValue, tfmaskChar)
		line = fmt.Sprintf("%v%v%v%v\"%v\"",
			match.leadingWhitespace,
			match.property,
			match.assignmentOperator,
			match.trailingWhitespaceAfter,
			maskedValue)
	}
	return line
}

type genericMatch struct {
	property string
	secrets  []string
}

func assignmentJSON(reg, reTfValues *regexp.Regexp, tfmaskChar, line string) []string {
	match := matchFromJSON(reg, line)
	if reTfValues.MatchString(match.property) {
		return match.secrets

	}
	return []string{}
}

func maskValue(value, tfmaskChar string) string {
	exclusions := []string{
		"sensitive",
		"computed",
		"<computed",
		"known after apply",
	}
	if !contains(exclusions, value) {
		return strings.Repeat(tfmaskChar, utf8.RuneCountInString(value))
	}
	return value
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
