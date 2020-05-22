package openid

import (
    "net/url"
    "strings"
)

// For SregFields,
// its key is the registration field (after removing the prefix 'openid.sreg')
// its value is whether that field is optional
func SetSregFields(fields map[string]bool) {
    oid := defaultInstance
    if oid.sregFields == nil {
        oid.sregFields = fields
    } else {
        for k, v := range fields {
            SetSregField(k, v)
        }
    }
}

func SetSregField(field string, isOptional bool) {
    defaultInstance.sregFields[field] = isOptional
}

// OpenID Simple Registration Extension 1.0
// 3. Request Format
// openid.sreg.required:
// Comma-separated list of field names which, if absent from the response, will prevent the Consumer from completing the
// registration without End User interation. The field names are those that are specified in the Response Format, with
// the "openid.sreg." prefix removed.
// openid.sreg.optional:
// Comma-separated list of field names Fields that will be used by the Consumer, but whose absence will not prevent the
// registration from completing. The field names are those that are specified in the Response Format, with the
// "openid.sreg." prefix removed.
// openid.sreg.policy_url:
// TODO: sreg.policy_url have not been implemented
func setSregQueryValues(val *url.Values) {
    var optional, required []string
    for k, v := range defaultInstance.sregFields {
        if v {
            optional = append(optional, k)
        } else {
            required = append(required, k)
        }
    }
    val.Add("openid.sreg.optional", strings.Join(optional, ","))
    val.Add("openid.sreg.required", strings.Join(required, ","))
}