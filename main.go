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

type expression struct {
	planStatusRegex         *regexp.Regexp
	reTfPlanLine            *regexp.Regexp
	reTfPlanCurrentResource *regexp.Regexp
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
	"0.11": expression{
		planStatusRegex: regexp.MustCompile(
			"^(.*?): (.*?) +\\(ID: (.*?)\\)$",
		),
		reTfPlanLine: regexp.MustCompile(
			"^( +)([a-zA-Z0-9%._-]+):( +)([\"<])(.*?)([>\"]) +=> +([\"<])(.*)([>\"])(.*)$",
		),
		reTfPlanCurrentResource: regexp.MustCompile(
			"^([~/+-]+) (.*?) +(.*)$",
		),
		resourceIndex: 2,
		assign:        ":",
		operator:      "=>",
	},
	"0.12": expression{
		planStatusRegex: regexp.MustCompile(
			"^(.*?): (.*?) +\\[id=(.*?)\\]$",
		),
		reTfPlanLine: regexp.MustCompile(
			"^( +)([ +~a-zA-Z0-9%._-]+)=( +)([\"<])(.*?)([>\"])( +-> +?(\\()(.*)(\\))(.*))?$",
		),
		reTfPlanCurrentResource: regexp.MustCompile(
			"^([~/+-]+|^\\s+[~/+-]+) (.*?) +(.*) (.*) (.*)$",
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
		"(?i)^.*(oauth|secret|token|password|key|result|id).*$")
	// Pattern representing sensitive resource
	var tfmaskResourceRegex = getEnv("TFMASK_RESOURCES_REGEX",
		"(?i)^(random_id|random_string).*$")

	// Default to tf 0.11, but users can override
	var tfenv = getEnv("TFENV", "0.12")

	reTfValues := regexp.MustCompile(tfmaskValuesRegex)
	reTfResource := regexp.MustCompile(tfmaskResourceRegex)
	scanner := bufio.NewScanner(os.Stdin)
	versionedExpressions := versionedExpressions[tfenv]
	// initialise currentResource once before scanning
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

func processLine(expression expression, reTfResource,
	reTfValues *regexp.Regexp, tfmaskChar, currentResource,
	line string) string {
	if expression.planStatusRegex.MatchString(line) {
		line = planStatus(expression.planStatusRegex, reTfResource, tfmaskChar,
			line)
	} else if expression.reTfPlanLine.MatchString(line) {
		line = planLine(expression.reTfPlanLine, reTfResource, reTfValues,
			currentResource, tfmaskChar, expression.assign,
			expression.operator, line)
	}
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

func matchFromLine(reTfPlanLine *regexp.Regexp, line string) match {
	subMatch := reTfPlanLine.FindStringSubmatch(line)
	subMatchLength := len(subMatch)
	if subMatchLength == 12 {
		return match {
			leadingWhitespace:  subMatch[1],
			property:           subMatch[2], // something like `stage.0.action.0.configuration.OAuthToken`
			trailingWhitespace: subMatch[3],
			firstQuote:         subMatch[4],
			oldValue:           subMatch[5],
			secondQuote:        subMatch[6], // > or "
			thirdQuote:         subMatch[8], // < or " or (
			newValue:           subMatch[9],
			fourthQuote:        subMatch[10], // > or " or )
			postfix:            subMatch[11],
		}
	} else {
		return match {
			leadingWhitespace:  subMatch[1],
			property:           subMatch[2], // something like `stage.0.action.0.configuration.OAuthToken`
			trailingWhitespace: subMatch[3],
			firstQuote:         subMatch[4],
			oldValue:           subMatch[5],
			secondQuote:        subMatch[6], // > or "
			thirdQuote:         subMatch[7], // < or " or (
			newValue:           subMatch[8],
			fourthQuote:        subMatch[9], // > or " or )
			postfix:            subMatch[10],
		}
	}
}

func planLine(reTfPlanLine, reTfResource, reTfValues *regexp.Regexp,
	currentResource, tfmaskChar, assign, operator, line string) string {
	match := matchFromLine(reTfPlanLine, line)
	if reTfValues.MatchString(match.property) ||
		reTfResource.MatchString(currentResource) {
		// The value inside the "...", <...> or (...)
		oldValue := maskValue(match.oldValue, tfmaskChar)
		// The value inside the "...", <...> or (...)
		newValue := maskValue(match.newValue, tfmaskChar)
		if match.newValue == "" {
			line = fmt.Sprintf("%v%v%v%v%v%v%v %v%v%v%v",
				match.leadingWhitespace, match.property, assign,
				match.trailingWhitespace, match.firstQuote, oldValue,
				match.secondQuote, match.thirdQuote,
				newValue, match.fourthQuote, match.postfix)
		} else {
			line = fmt.Sprintf("%v%v%v%v%v%v%v %v %v%v%v%v",
				match.leadingWhitespace, match.property, assign,
				match.trailingWhitespace, match.firstQuote, oldValue,
				match.secondQuote, operator, match.thirdQuote,
				newValue, match.fourthQuote, match.postfix)
		}
	}
	return line
}

func maskValue(value, tfmaskChar string) string {
	exclusions := []string{"sensitive", "computed", "<computed",
		"known after apply"}
	if !contains(exclusions, value) {
		return strings.Repeat(tfmaskChar,
			utf8.RuneCountInString(value))
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
