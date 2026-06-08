# goipa - FreeIPA client library
===============================================================================

[![GoDoc](https://img.shields.io/badge/godoc-reference-blue)](https://pkg.go.dev/github.com/ubccr/goipa)

goipa is a [FreeIPA](http://www.freeipa.org/) client library written in Go.
It interfaces with the FreeIPA JSON [api](https://github.com/freeipa/freeipa/blob/master/API.txt)
over HTTPS.

## Usage

Install using go tools:

```
$ go get github.com/ubccr/goipa
```

Example calling FreeIPA user-show:

```go
package main

import (
    "fmt"

    "github.com/ubccr/goipa"
)

func main() {
    client := ipa.NewDefaultClient()

    err := client.LoginWithKeytab("/path/to/user.keytab", "username")
    if err != nil {
        panic(err)
    }

    rec, err := client.UserShow("username")
    if err != nil {
        panic(err)
    }

    fmt.Println("%s - %s", rec.Username, rec.Uid)
}
```

## Hacking

Development and testing goipa uses docker-compose. The scripts to spin up a
FreeIPA test server in docker were copied/adopted from [this great repository](https://github.com/adelton/webauthinfra). 
Most of the scripts in `container/` directory are written by Jan Pazdziora and
licensed under Apache 2.0 and modified for use with goipa.

NOTE: The containers are NOT meant to be run in production and used solely for
development.

To get started hacking on goipa and running the test suite:

```
$ cp .env.sample .env
[edit to taste. add passwords and ssh key]

$ docker-compose build
$ docker-compose up -d
$ ssh -p 9022 localhost
$ kinit admin
$ cd /app
$ go test
```

To run a specific test with trace debugging:

```
$ go test -v -run UserShow
```

## License

goipa is released under a BSD style License. See the LICENSE file.
