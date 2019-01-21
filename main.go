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
	var tfmaskRegex = getEnv("TFMASK_REGEX", "(?i)^.*(oauth|secret|token|password|key).*$")

	// stage.0.action.0.configuration.OAuthToken: "" => "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	reTfPlanLine := regexp.MustCompile("^( +)([a-zA-Z0-9%._-]+):( +)\"(.*?)\" +=> +\"(.*?)\"")
	reTfSensitive := regexp.MustCompile(tfmaskRegex)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if reTfPlanLine.MatchString(line) {
			match := reTfPlanLine.FindStringSubmatch(line)
			leadingWhitespace := match[1]
			property := match[2]
			trailingWhitespace := match[3]

			if reTfSensitive.MatchString(property) {
				oldValue := strings.Repeat(tfmaskChar, utf8.RuneCountInString(match[4]))
				newValue := strings.Repeat(tfmaskChar, utf8.RuneCountInString(match[5]))
				fmt.Printf("%v%v:%v\"%v\" => \"%v\"\n", leadingWhitespace, property, trailingWhitespace, oldValue, newValue)
			} else {
				fmt.Println(line)
			}
		} else {
			fmt.Println(line)
		}
	}

  	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}