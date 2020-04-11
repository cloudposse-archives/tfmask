package main

import (
	"regexp"
	"strings"
	"testing"
)

var lineTests = []struct {
	line           string
	expectedResult string
	minorVersion   string
}{
	// tf 0.11 ------------------------------------
	{"not_secret", "not_secret", "0.11"},
	{" stage.0.action.0.configuration.OAuthToken: <wefwf> => <dfdff> ",
		" stage.0.action.0.configuration.OAuthToken: <*****> => <*****> ", "0.11"},
	{" stage.0.action.0.configuration.OAuthToken: \"wefwf\" => \"dfdff\" ",
		" stage.0.action.0.configuration.OAuthToken: \"*****\" => \"*****\" ", "0.11"},
	{" stage.0.action.0.configuration.DontObfuscate: <wefwf> => <dfdff> ",
		" stage.0.action.0.configuration.DontObfuscate: <wefwf> => <dfdff> ", "0.11"},
	{"random_id.some_id: Refreshing state... (ID: itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ)",
		"random_id.some_id: Refreshing state... (ID: ********************************************************************************)",
		"0.11"},
	{"random_string.some_password: Refreshing state... (ID: 2iB@@h22@12kA2qE)",
		"random_string.some_password: Refreshing state... (ID: ****************)",
		"0.11"},
	// tf 0.12 ------------------------------------
	{"not_secret", "not_secret", "0.12"},
	{" stage.0.action.0.configuration.OAuthToken: <wefwf> => <dfdff> ",
		" stage.0.action.0.configuration.OAuthToken: <*****> => <*****> ", "0.12"},
	{" stage.0.action.0.configuration.OAuthToken: \"wefwf\" => \"dfdff\" ",
		" stage.0.action.0.configuration.OAuthToken: \"*****\" => \"*****\" ", "0.12"},
	{" stage.0.action.0.configuration.DontObfuscate: <wefwf> => <dfdff> ",
		" stage.0.action.0.configuration.DontObfuscate: <wefwf> => <dfdff> ", "0.12"},
	{"random_id.some_id: Refreshing state... [id=itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ]",
		"random_id.some_id: Refreshing state... [id=********************************************************************************]",
		"0.12"},
	{"random_string.some_password: Refreshing state... [id=2iB@@h22@12kA2qE]",
		"random_string.some_password: Refreshing state... [id=****************]",
		"0.12"},
}

func TestProcessLine(t *testing.T) {
	for _, lineTest := range lineTests {
		line := lineTest.line
		// Character used to mask sensitive output
		var tfmaskChar = "*"
		// Pattern representing sensitive output
		var tfmaskValuesRegex = "(?i)^.*(oauth|secret|token|password|key|result).*$"
		// Pattern representing sensitive resource
		var tfmaskResourceRegex = "(?i)^(random_id|random_string).*$"
		// stage.0.action.0.configuration.OAuthToken: "" => "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		reTfPlanLine := regexp.MustCompile("^( +)([a-zA-Z0-9%._-]+):( +)([\"<])(.*?)([>\"]) +=> +([\"<])(.*)([>\"])(.*)$")
		currentResource := getCurrentResource(line)
		reTfValues := regexp.MustCompile(tfmaskValuesRegex)
		reTfResource := regexp.MustCompile(tfmaskResourceRegex)
		result := processLine(versionedExpressions[lineTest.minorVersion],
			reTfPlanLine, reTfResource, reTfValues, tfmaskChar, currentResource, line)
		result = strings.TrimSuffix(result, "\n")
		expectedResult := lineTest.expectedResult
		if result != expectedResult {
			t.Errorf("Got %s, want %s", result, expectedResult)
		}
	}
}

func TestGetCurrentResource(t *testing.T) {
	result := getCurrentResource("-/+ random_string.postgres_admin_password (tainted) (new resource required)")
	expectedResult := "random_string.postgres_admin_password"
	if result != expectedResult {
		t.Errorf("Got %s, want %s", result, expectedResult)
	}
}

var planStatusTests = []struct {
	line           string
	expectedResult string
	minorVersion   string
}{
	// tf 0.11 ------------------------------------
	{
		"random_id.some_id: Refreshing state... (ID: itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ)",
		"random_id.some_id: Refreshing state... (ID: ********************************************************************************)",
		"0.11",
	},
	{
		"random_string.some_password: Refreshing state... (ID: 2iB@@h22@12kA2qE)",
		"random_string.some_password: Refreshing state... (ID: ****************)",
		"0.11",
	},
	// tf 0.12 ------------------------------------
	{
		"random_id.some_id: Refreshing state... [id=itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ]",
		"random_id.some_id: Refreshing state... [id=********************************************************************************]",
		"0.12",
	},
	{
		"random_string.some_password: Refreshing state... [id=2iB@@h22@12kA2qE]",
		"random_string.some_password: Refreshing state... [id=****************]",
		"0.12",
	},
}

func TestPlanStatus(t *testing.T) {
	var tfmaskResourceRegex = regexp.MustCompile("(?i)^(random_id|random_string).*$")
	for _, planStatusTest := range planStatusTests {
		result := planStatus(
			versionedExpressions[planStatusTest.minorVersion].planStatusRegex,
			tfmaskResourceRegex, "*",
			planStatusTest.line)
		if result != planStatusTest.expectedResult {
			t.Errorf("Got %s, want %s", result, planStatusTest.expectedResult)
		}
	}
}
