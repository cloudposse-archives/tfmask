package main

import (
	"regexp"
	"strings"
	"testing"
)

var lineTests = []struct {
	currentResource string
	line            string
	expectedResult  string
	minorVersion    string
}{
	// tf 0.11 ------------------------------------
	{"random_id.some_id", "not_secret", "not_secret", "0.11"},
	{"random_id.some_id", " stage.0.action.0.configuration.OAuthToken: <tf.0.11> => <tf.0.11> ",
		" stage.0.action.0.configuration.OAuthToken: <*******> => <*******> ", "0.11"},
	{"random_id.some_id", " stage.0.action.0.configuration.OAuthToken: \"tf.0.11\" => \"tf.0.11\" ",
		" stage.0.action.0.configuration.OAuthToken: \"*******\" => \"*******\" ", "0.11"},
	{"random_id.some_id", " stage.0.action.0.configuration.DontObfuscate: <tf.0.11> => <tf.0.11> ",
		" stage.0.action.0.configuration.DontObfuscate: <*******> => <*******> ", "0.11"},
	{"random_id.some_id", "random_id.some_id: Refreshing state... (ID: itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ)",
		"random_id.some_id: Refreshing state... (ID: ********************************************************************************)",
		"0.11"},
	{"random_string.some_password", "random_string.some_password: Refreshing state... (ID: 2iB@@h22@12kA2qE)",
		"random_string.some_password: Refreshing state... (ID: ****************)",
		"0.11"},
	{"random_id.some_id", " id:               \"VIxvs2TloohI2XtAsHyu68wQvFQQCTOGgsglqC7zKjsnOmUMIMrZ1y5J6ieOIzl-YXiS1_XmVc8J8gb9fIcwIA\" => <computed> (forces new resource)",
		" id:               \"**************************************************************************************\" => <computed> (forces new resource)",
		"0.11"},
	// tf 0.12 ------------------------------------
	{"random_id.some_id", "not_secret", "not_secret", "0.12"},
	{"random_id.some_id", "      ~ result           = \"pkwemfpwmfwf\" -> (known after apply) ",
		"      ~ result           = \"************\" -> (known after apply) ", "0.12"},
	{"random_id.some_id", "random_id.some_id: Refreshing state... [id=itILf4x5lqleQV9ZwT2gH-Zg3yuXM8pdUu6VFTX...P5vqUmggDweOoxFMPY5t9thA0SJE2EZIhcHbsQ]",
		"random_id.some_id: Refreshing state... [id=********************************************************************************]",
		"0.12"},
	{"", "random_id.some_id: Creation complete after 0s [id=YfK9aF]",
		"random_id.some_id: Creation complete after 0s [id=******]",
		"0.12"},
	{"random_string.some_password", "random_string.some_password: Refreshing state... [id=2iB@@h22@12kA2qE]",
		"random_string.some_password: Refreshing state... [id=****************]",
		"0.12"},
	{"random_id.some_id", " ~ id =               \"VIxvs2TloohI2XtAsHyu68wQvFQQCTOGgsglqC7zKjsnOmUMIMrZ1y5J6ieOIzl-YXiS1_XmVc8J8gb9fIcwIA\" -> (known after apply)",
		" ~ id =               \"**************************************************************************************\" -> (known after apply)",
		"0.12"},
	{"", "random_string.some_password: Creation complete after 0s [id=5s80SMs@JJpA8e/h]",
		"random_string.some_password: Creation complete after 0s [id=****************]",
		"0.12"},
	{"", "      + token       = \"abC123ABc\"",
		"      + token       = \"*********\" ",
		"0.12"},
}

func TestProcessLine(t *testing.T) {
	for _, lineTest := range lineTests {
		line := lineTest.line
		// Character used to mask sensitive output
		var tfmaskChar = "*"
		// Pattern representing sensitive output
		var tfmaskValuesRegex = "(?i)^.*(oauth|secret|token|password|key|result|id).*$"
		// Pattern representing sensitive resource
		var tfmaskResourceRegex = "(?i)^(random_id|random_string).*$"

		versionedExpressions := versionedExpressions[lineTest.minorVersion]

		currentResource := lineTest.currentResource
		reTfValues := regexp.MustCompile(tfmaskValuesRegex)
		reTfResource := regexp.MustCompile(tfmaskResourceRegex)
		result := processLine(versionedExpressions,
			reTfResource, reTfValues, tfmaskChar, currentResource, line)
		result = strings.TrimSuffix(result, "\n")
		expectedResult := lineTest.expectedResult
		if result != expectedResult {
			t.Errorf("Got %s, want %s", result, expectedResult)
		}
	}
}

var currentResourceTests = []struct {
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
	for _, currentResourceTest := range currentResourceTests {
		result := getCurrentResource(versionedExpressions["0.11"], currentResourceTest.currentResource,
			currentResourceTest.line)
		expectedResult := currentResourceTest.expectedResult
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

var maskValueTests = []struct {
	value          string
	tfmaskChar     string
	expectedResult string
}{
	{"password", "*", "********"},
	{"password", "@", "@@@@@@@@"},
	{"sensitive", "*", "sensitive"},
	{"computed", "*", "computed"},
	{"<computed", "*", "<computed"},
	{"known after apply", "*", "known after apply"},
}

func TestMaskValue(t *testing.T) {
	for _, maskValueTest := range maskValueTests {
		result := maskValue(maskValueTest.value, maskValueTest.tfmaskChar)
		if result != maskValueTest.expectedResult {
			t.Errorf("Got %s, want %s", result, maskValueTest.expectedResult)
		}
	}
}

var assignmentTests = []struct {
	line           string
	expectedResult string
	minorVersion   string
}{
	// tf 0.11 ------------------------------------
	{
		" + client_secret: \"123456\"",
		" + client_secret: \"******\"",
		"0.11",
	},
	{
		" + client_secret = \"123456\"",
		" + client_secret = \"******\"",
		"0.11",
	},
	// tf 0.12 ------------------------------------
	{
		" + \"foo_secret\" = \"123456\"",
		" + \"foo_secret\" = \"******\"",
		"0.12",
	},
	{
		" + foo_secret = \"123456\"",
		" + foo_secret = \"******\"",
		"0.12",
	},
	{
		" - \"foo_secret\" = \"123456\"",
		" - \"foo_secret\" = \"******\"",
		"0.12",
	},
	{
		" ~ \"foo_secret\" = \"123456\"",
		" ~ \"foo_secret\" = \"******\"",
		"0.12",
	},
	{
		" ~ \"foo\" = \"123456\"",
		" ~ \"foo\" = \"123456\"",
		"0.12",
	},
	{
		" \"foo_secret\" = \"123456\"",
		" \"foo_secret\" = \"******\"",
		"0.12",
	},
}

func TestAssignmentLine(t *testing.T) {
	// Character used to mask sensitive output
	var tfmaskChar = "*"
	// Pattern representing sensitive output
	var tfmaskValuesRegex = "(?i)^.*[^a-zA-Z](oauth|secret|token|password|key|result|id).*$"
	reTfValues := regexp.MustCompile(tfmaskValuesRegex)

	for _, assignmentTest := range assignmentTests {
		result := assignmentLine(
			versionedExpressions[assignmentTest.minorVersion].reMapKeyPair,
			reTfValues, tfmaskChar,
			assignmentTest.line)
		if result != assignmentTest.expectedResult {
			t.Errorf("Got %s, want %s", result, assignmentTest.expectedResult)
		}
	}
}
