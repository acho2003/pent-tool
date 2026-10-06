package scanner

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestNativeArtifactsSanitizeUnknownCredentialsWithoutBreakingRecords(t *testing.T) {
	fixtures := []struct{ path, raw string }{
		{"results.json", `{"id":9007199254740993,"method":"POST","url":"https://user:urlsecret@app.test/a%2Fb?x=1&x=2&access_token=querysecret","headers":{"Cookie":"unknowncookie","Authorization":"Bearer unknownbearer"},"nested":[{"password":"quote\"secret"}],"evidence":"Cookie: first=unknownfirst; second=unknownsecond\r\nGET /"}`},
		{"results.jsonl", "{\"id\":1,\"token\":\"unknowntoken\"}\n{\"id\":2,\"evidence\":\"Bearer unknownbearer\"}\n"},
		{"results.xml", `<report id="native"><result id="one"><password>xmlsecret</password><description>Authorization: Bearer unknownbearer</description><url>https://app.test/a?token=querysecret&amp;x=1</url></result></report>`},
		{"results.txt", "Cookie: first=unknownfirst; second=unknownsecond\nAuthorization: Bearer unknownbearer\nhttps://app.test/a?token=querysecret&x=1\npassword=assignmentsecret"},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.path, func(t *testing.T) {
			data, err := sanitizeArtifactData(fixture.path, []byte(fixture.raw), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"urlsecret", "querysecret", "unknowncookie", "unknownbearer", "quote", "unknownfirst", "unknownsecond", "unknowntoken", "xmlsecret", "assignmentsecret"} {
				if strings.Contains(string(data), secret) {
					t.Fatalf("secret %s leaked: %s", secret, data)
				}
			}
			if strings.HasSuffix(fixture.path, ".json") {
				if !json.Valid(data) || !strings.Contains(string(data), "9007199254740993") || !strings.Contains(string(data), "a%2Fb?x=1&x=2") {
					t.Fatalf("native semantics lost: %s", data)
				}
			}
			if strings.HasSuffix(fixture.path, ".xml") {
				decoder := xml.NewDecoder(bytes.NewReader(data))
				for {
					_, err := decoder.Token()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if !strings.Contains(string(data), `id="one"`) {
					t.Fatal("native identity lost")
				}
			}
		})
	}
}

func TestMalformedArtifactsCannotBypassSanitization(t *testing.T) {
	for _, fixture := range []struct{ path, raw string }{{"bad.json", `{"token":"secret"`}, {"bad.json", `{} {}`}, {"bad.jsonl", "{}\n{bad"}, {"bad.xml", "<report><token>secret</report>"}, {"empty.json", ""}} {
		if _, err := sanitizeArtifactData(fixture.path, []byte(fixture.raw), nil); err == nil {
			t.Fatalf("unsafe %s accepted", fixture.path)
		}
	}
}
