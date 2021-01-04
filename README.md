# go-jwt
Implementation of Jwt in golang.

## Installation

```shell
go get github.com/MangoMilk/go-jwt
```

## QuickStart
```go
import (
    "strconv"
    "github.com/MangoMilk/go-jwt"
)

const SECRET = "secret"

func main() {
    // generate 
    jwt := Jwt.NewJwt()

    jwt.SetStandardPayload(Jwt.StandardPayload{
        Iss: "Dwarf",
        Iat: strconv.Itoa(int(time.Now().Unix())),
    })
    
    additionPayload := make(map[string]interface{})
    additionPayload["username"] = "dwarf"
    jwt.SetAdditionPayload(additionPayload)
    
    setHeaderErr :=jwt.SetHeader(Header{Alg: Jwt.HS256})
    if setHeaderErr != nil {
        panic(setHeaderErr)
    }
 
    var token string
    signErr := jwt.Signature(SECRET)
    if signErr != nil {
        panic(signErr)
    }

    token = jwt.Generate()
    fmt.Printf("token: ", token)

    // verify
    jwt2 := Jwt.NewJwt()
    resolveErr := jwt2.Resolve(token)
    if resolveErr == nil {
        panic(resolveErr)
    }

    fmt.Println(jwt2.VerifySign(SECRET) == nil)
    //fmt.Println("header: ", jwt2.Header))
    //fmt.Println("payload: ", jwt2.Payload))
}
```
