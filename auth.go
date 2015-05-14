package main

import (
    "fmt"
    "errors"
    "encoding/json"
    "io/ioutil"
    "crypto/tls"
    "crypto/x509"
    "net/http"
    "github.com/spf13/viper"
)


// This function authenticates users against the "old" ccr kerberos servers
func ccrAuth(user, pass string) error {
    pem, err := ioutil.ReadFile(viper.GetString("ccrcrt"))
    if err != nil {
        return err
    }

    certPool := x509.NewCertPool()
    if !certPool.AppendCertsFromPEM(pem) {
        return errors.New("Failed appending certs")
    }

    config := &tls.Config{RootCAs: certPool, InsecureSkipVerify: false}
    tr := &http.Transport{
        TLSClientConfig: config,
    }

    client := &http.Client{Transport: tr}
    req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", viper.GetString("ccrsrv")), nil)
    req.SetBasicAuth(user, pass)

    res, err := client.Do(req)
    if err != nil {
        return err
    }
    defer res.Body.Close()

    if res.StatusCode != 200 {
        return fmt.Errorf("ccrauth failed with HTTP status code: %d", res.StatusCode)
    }

    decoder := json.NewDecoder(res.Body)
    var rec map[string]string
    err = decoder.Decode(&rec)
    if err != nil {
        return err
    }

    if _, ok := rec["uid"]; !ok {
        return errors.New("ccrauth invalid json returned")
    }

    if rec["uid"] != user {
        return errors.New("ccrauth invalid uid in json")
    }

    return nil
}
