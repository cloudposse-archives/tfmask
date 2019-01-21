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

func main() {
	log.SetFlags(0) // no timestamps on our logs

	// Character used to mask sensitive output
	var tfmaskChar = getEnv("TFMASK_CHAR", "*")

	// Pattern representing sensitive output
	var tfmaskValuesRegex = getEnv("TFMASK_VALUES_REGEX", "(?i)^.*(oauth|secret|token|password|key|result).*$")

	// Pattern representing sensitive resource
	var tfmaskResourceRegex = getEnv("TFMASK_RESOURCE_REGEX", "(?i)^(random_id).*$")

	// stage.0.action.0.configuration.OAuthToken: "" => "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	reTfPlanLine := regexp.MustCompile("^( +)([a-zA-Z0-9%._-]+):( +)([\"<])(.*?)([>\"]) +=> +([\"<])(.*?)([>\"])(.*)$")

	// random_id.some_id: Refreshing state... (ID: itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ)
	reTfPlanStatusLine := regexp.MustCompile("^(.*?): (.*?) +\\(ID: (.*?)\\)$")
	

	// -/+ random_string.postgres_admin_password (tainted) (new resource required)
	reTfPlanCurrentResource := regexp.MustCompile("^([~/+-]+) (.*?) +(.*)$")
	reTfApplyCurrentResource := regexp.MustCompile("^([a-z].*?): (.*?)$")
	currentResource := ""

	reTfValues := regexp.MustCompile(tfmaskValuesRegex)
	reTfResource := regexp.MustCompile(tfmaskResourceRegex)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if reTfPlanCurrentResource.MatchString(line) {
			match := reTfPlanCurrentResource.FindStringSubmatch(line)
			currentResource = match[2]
		} else if reTfApplyCurrentResource.MatchString(line) {
			match := reTfApplyCurrentResource.FindStringSubmatch(line)
			currentResource = match[1]
		}

		if reTfPlanStatusLine.MatchString(line) {
			match := reTfPlanStatusLine.FindStringSubmatch(line)
			resource := match[1]
			id := match[3]
			if reTfResource.MatchString(resource) {
				line = strings.Replace(line, id, strings.Repeat(tfmaskChar, utf8.RuneCountInString(id)), 1)
			}
			fmt.Println(line)
		} else if reTfPlanLine.MatchString(line) {
			match := reTfPlanLine.FindStringSubmatch(line)
			leadingWhitespace := match[1]
			property := match[2]            // something like `stage.0.action.0.configuration.OAuthToken`
			trailingWhitespace := match[3]
			firstQuote := match[4]          // < or "
			oldValue := match[5] 
			secondQuote := match[6]         // > or "
			thirdQuote := match[7]          // < or "
			newValue := match[8]
			fourthQuote := match[9]         // > or "
			postfix := match[10]

			if reTfValues.MatchString(property) || reTfResource.MatchString(currentResource) {
				// The value inside the "..." or <...>
				if oldValue != "sensitive" && oldValue != "computed" && oldValue != "<computed" {
					oldValue = strings.Repeat(tfmaskChar, utf8.RuneCountInString(oldValue))
				}
				// The value inside the "..." or <...>
				if newValue != "sensitive" && newValue != "computed" && newValue != "<computed" {
					newValue = strings.Repeat(tfmaskChar, utf8.RuneCountInString(newValue))
				}
				fmt.Printf("%v%v:%v%v%v%v => %v%v%v%v\n", 
					leadingWhitespace, property, trailingWhitespace, firstQuote, oldValue, secondQuote, thirdQuote, newValue, fourthQuote, postfix)
			} else {
				fmt.Println(line)
			}
		} else {
			// We matched nothing
			fmt.Println(line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
