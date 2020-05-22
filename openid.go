package openid

import (
	"net/http"
)

type OpenID struct {
	urlGetter httpGetter
	sregFields map[string]bool
}

func NewOpenID(client *http.Client) *OpenID {
	return &OpenID{urlGetter: &defaultGetter{client: client}, sregFields: nil}
}

var defaultInstance = NewOpenID(http.DefaultClient)
