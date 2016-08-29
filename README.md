# JSON Web Token wrapper package for GoLang

### Installation
```
go get github.com/ausrasul/jwt
```

#### Encryption key

On a linux based system, create a key pair to use for token encryption.
```
$ openssl genrsa -out privkey.pem 2048
$ openssl rsa -in privkey.pem -pubout -out pubkey.pem
```

Then use "privkey.pem" and "pubkey.pem" in the package configuration, see "Usage example"

### Usage:

This package can be used as stand alone to create, parse and refresh json web tokens
Note that the refresh happens automatically when a new Parse instruction comes in.

### Usage example:

```
package main

import (
   "github.com/ausrasul/jwt"
)

func main(){
	// Configure the package
	
	jwt.Configure(
		map[string]interface{}{
			"privateKeyFile":         "privkey.pem",
			"publicKeyFile":          "pubkey.pem",
			"algorithm":              "RS256",
			"sessionName":            "My_application_name_no_spaces",
			"sessionTimeout":         3000, // seconds
			"sessionRefreshInterval": 300, //seconds
		},
	)
	
	userAttributes := make (map[string]interface{})
	// populate the map with user attributes.
	
	// Now use the JWT part
	token, err := jwt.CreateToken(userAttributes, res, req)
	/* the resulting token is saved directly to the http responseWriter. */
	
	// Now you can parse a token into a user
	userAttributes = goJwt.ParseToken(token, res, req)
	/* the result is a user attributes map[string]interface.
		if the session has reached the sessionRefreshInterval, it will be refereshed
		automatically, otherwise if it passes the sessionTimeout, you'll get
		an error */
}

```
