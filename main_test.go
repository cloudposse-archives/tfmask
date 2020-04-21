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
		" stage.0.action.0.configuration.DontObfuscate: <*****> => <*****> ", "0.11"},
	{"random_id.some_id: Refreshing state... (ID: itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ)",
		"random_id.some_id: Refreshing state... (ID: ********************************************************************************)",
		"0.11"},
	// the id value isn't sensitive with random_string.some_password
	{"random_string.some_password: Refreshing state... (ID: 2iB@@h22@12kA2qE)",
		"random_string.some_password: Refreshing state... (ID: 2iB@@h22@12kA2qE)",
		"0.11"},
	{" id:               \"VIxvs2TloohI2XtAsHyu68wQvFQQCTOGgsglqC7zKjsnOmUMIMrZ1y5J6ieOIzl-YXiS1_XmVc8J8gb9fIcwIA\" => <computed> (forces new resource)",
		" id:               \"**************************************************************************************\" => <computed> (forces new resource)",
		"0.11"},
	// tf 0.12 ------------------------------------
	{"not_secret", "not_secret", "0.12"},
	{" stage.0.action.0.configuration.OAuthToken: <wefwf> => <dfdff> ",
		" stage.0.action.0.configuration.OAuthToken: <*****> => <*****> ", "0.12"},
	{" stage.0.action.0.configuration.OAuthToken: \"wefwf\" => \"dfdff\" ",
		" stage.0.action.0.configuration.OAuthToken: \"*****\" => \"*****\" ", "0.12"},
	{" stage.0.action.0.configuration.DontObfuscate: <wefwf> => <dfdff> ",
		" stage.0.action.0.configuration.DontObfuscate: <*****> => <*****> ", "0.12"},
	{"random_id.some_id: Refreshing state... [id=itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ]",
		"random_id.some_id: Refreshing state... [id=********************************************************************************]",
		"0.12"},
	// the id value isn't sensitive with random_string.some_password
	{"random_string.some_password: Refreshing state... [id=2iB@@h22@12kA2qE]",
		"random_string.some_password: Refreshing state... [id=2iB@@h22@12kA2qE]",
		"0.12"},
	{" id:               \"VIxvs2TloohI2XtAsHyu68wQvFQQCTOGgsglqC7zKjsnOmUMIMrZ1y5J6ieOIzl-YXiS1_XmVc8J8gb9fIcwIA\" => <computed> (forces new resource)",
		" id:               \"**************************************************************************************\" => <computed> (forces new resource)",
		"0.11"},
}

func TestProcessLine(t *testing.T) {
	for _, lineTest := range lineTests {
		line := lineTest.line
		// Character used to mask sensitive output
		var tfmaskChar = "*"
		// Pattern representing sensitive output
		var tfmaskValuesRegex = "(?i)^.*(oauth|secret|token|password|key|result).*$"
		// Pattern representing sensitive resource
		var tfmaskResourceRegex = "(?i)^(random_id).*$"
		// stage.0.action.0.configuration.OAuthToken: "" => "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		reTfPlanLine := regexp.MustCompile("^( +)([a-zA-Z0-9%._-]+):( +)([\"<])(.*?)([>\"]) +=> +([\"<])(.*)([>\"])(.*)$")
		currentResource := getCurrentResource("random_id.some_id", line)
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

var currrentResourceTests = []struct {
	currentResource string
	line            string
	expectedResult  string
}{
	{"", "-/+ random_string.postgres_admin_password (tainted) (new resource required)",
		"random_string.postgres_admin_password",
	},
	// existing currentResource should persist:
	{
		"random_string.postgres_admin_password",
		" id:               \"VIxvs2TloohI2XtAsHyu68wQvFQQCTOGgsglqC7zKjsnOmUMIMrZ1y5J6ieOIzl-YXiS1_XmVc8J8gb9fIcwIA\" => <computed> (forces new resource)",
		"random_string.postgres_admin_password",
	},
}

func TestGetCurrentResource(t *testing.T) {
	for _, currrentResourceTest := range currrentResourceTests {
		result := getCurrentResource(currrentResourceTest.currentResource,
			currrentResourceTest.line)
		expectedResult := currrentResourceTest.expectedResult
		if result != expectedResult {
			t.Errorf("Got %s, want %s", result, expectedResult)
		}
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
	// the id value isn't sensitive with random_string.some_password:
	{
		"random_string.some_password: Refreshing state... (ID: 2iB@@h22@12kA2qE)",
		"random_string.some_password: Refreshing state... (ID: 2iB@@h22@12kA2qE)",
		"0.11",
	},
	// tf 0.12 ------------------------------------
	{
		"random_id.some_id: Refreshing state... [id=itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ]",
		"random_id.some_id: Refreshing state... [id=********************************************************************************]",
		"0.12",
	},
	// the id value isn't sensitive with random_string.some_password:
	{
		"random_string.some_password: Refreshing state... [id=2iB@@h22@12kA2qE]",
		"random_string.some_password: Refreshing state... [id=2iB@@h22@12kA2qE]",
		"0.12",
	},
}

func TestPlanStatus(t *testing.T) {
	var tfmaskResourceRegex = regexp.MustCompile("(?i)^(random_id).*$")
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
