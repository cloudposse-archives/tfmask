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
	thirdQuote         string // < or "
	newValue           string
	fourthQuote        string // > or "
	postfix            string
}

type expression struct {
	planStatusRegex *regexp.Regexp
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
			"^(.*?): (.*?) +\\(ID: (.*?)\\)$"),
	},
	"0.12": expression{
		planStatusRegex: regexp.MustCompile(
			"^(.*?): (.*?) +\\[id=(.*?)\\]$"),
	},
}

func main() {
	log.SetFlags(0) // no timestamps on our logs

	// Character used to mask sensitive output
	var tfmaskChar = getEnv("TFMASK_CHAR", "*")
	// Pattern representing sensitive output
	var tfmaskValuesRegex = getEnv("TFMASK_VALUES_REGEX",
		"(?i)^.*(oauth|secret|token|password|key|result).*$")
	// Pattern representing sensitive resource
	var tfmaskResourceRegex = getEnv("TFMASK_RESOURCES_REGEX",
		"(?i)^(random_id|random_string).*$")
	// stage.0.action.0.configuration.OAuthToken: "" => "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	reTfPlanLine := regexp.MustCompile("^( +)([a-zA-Z0-9%._-]+):( +)([\"<])(.*?)([>\"]) +=> +([\"<])(.*)([>\"])(.*)$")

	var tfenv = getEnv("TFENV", "0.11")

	reTfValues := regexp.MustCompile(tfmaskValuesRegex)
	reTfResource := regexp.MustCompile(tfmaskResourceRegex)
	scanner := bufio.NewScanner(os.Stdin)
	versionedExpressions := versionedExpressions[tfenv]
	for scanner.Scan() {
		line := scanner.Text()
		currentResource := getCurrentResource(line)
		fmt.Println(processLine(versionedExpressions, reTfPlanLine,
			reTfResource, reTfValues, tfmaskChar, currentResource, line))
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func getCurrentResource(line string) (currentResource string) {
	// -/+ random_string.postgres_admin_password (tainted) (new resource required)
	reTfPlanCurrentResource := regexp.MustCompile("^([~/+-]+) (.*?) +(.*)$")
	reTfApplyCurrentResource := regexp.MustCompile("^([a-z].*?): (.*?)$")
	if reTfPlanCurrentResource.MatchString(line) {
		match := reTfPlanCurrentResource.FindStringSubmatch(line)
		currentResource = match[2]
	} else if reTfApplyCurrentResource.MatchString(line) {
		match := reTfApplyCurrentResource.FindStringSubmatch(line)
		currentResource = match[1]
	}
	return
}

func processLine(expression expression, reTfPlanLine, reTfResource,
	reTfValues *regexp.Regexp, tfmaskChar, currentResource,
	line string) string {
	if expression.planStatusRegex.MatchString(line) {
		line = planStatus(expression.planStatusRegex, reTfResource, tfmaskChar,
			line)
	} else if reTfPlanLine.MatchString(line) {
		line = planLine(reTfPlanLine, reTfResource, reTfValues,
			currentResource, tfmaskChar, line)
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
	return match{
		leadingWhitespace:  subMatch[1],
		property:           subMatch[2], // something like `stage.0.action.0.configuration.OAuthToken`
		trailingWhitespace: subMatch[3],
		firstQuote:         subMatch[4],
		oldValue:           subMatch[5],
		secondQuote:        subMatch[6], // > or "
		thirdQuote:         subMatch[7], // < or "
		newValue:           subMatch[8],
		fourthQuote:        subMatch[9], // > or "
		postfix:            subMatch[10],
	}
}

func planLine(reTfPlanLine, reTfResource, reTfValues *regexp.Regexp,
	currentResource, tfmaskChar, line string) string {
	match := matchFromLine(reTfPlanLine, line)
	if reTfValues.MatchString(match.property) ||
		reTfResource.MatchString(currentResource) {
		// The value inside the "..." or <...>
		oldValue := maskValue(match.oldValue, tfmaskChar)
		// The value inside the "..." or <...>
		newValue := maskValue(match.newValue, tfmaskChar)
		line = fmt.Sprintf("%v%v:%v%v%v%v => %v%v%v%v\n",
			match.leadingWhitespace, match.property, match.trailingWhitespace,
			match.firstQuote, oldValue, match.secondQuote, match.thirdQuote,
			newValue, match.fourthQuote, match.postfix)
	}
	return line
}

func maskValue(value, tfmaskChar string) string {
	if value != "sensitive" && value != "computed" &&
		value != "<computed" {
		return strings.Repeat(tfmaskChar,
			utf8.RuneCountInString(value))
	}
	return value
}
