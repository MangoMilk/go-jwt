package jwt

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	// generate
	jwt := NewJwt()
	jwt.SetStandardPayload(StandardPayload{
		Iss: "Vincent",
		Iat: strconv.Itoa(int(time.Now().Unix())),
	})

	additionPayload := make(map[string]interface{})
	additionPayload["username"] = "dwarf"
	additionPayload["age"] = 18
	jwt.SetAdditionPayload(additionPayload)

	//t.Log(jwt.SetHeader(Header{Alg: HS1}))
	t.Log(jwt.Header.SetAlg(HS256))
	//t.Log(fmt.Sprintf("header: %+v", jwt.Header))
	//t.Log(fmt.Sprintf("payload: %+v", jwt.Payload))

	var token string
	signErr := jwt.Signature("mjj")
	//t.Log(signErr)
	if signErr == nil {
		token = jwt.Generate()
		t.Log(fmt.Sprintf("token: %+v", token))
	}

	// resolve
	jwt2 := NewJwt()
	resolveErr := jwt2.Resolve(token)
	//t.Log(resolveErr)
	if resolveErr == nil {
		//t.Log(fmt.Sprintf("header: %+v", jwt2.Header))
		//t.Log(fmt.Sprintf("payload: %+v", jwt2.Payload))
		t.Log(jwt2.VerifySign("mjj") == nil)
	}
}
