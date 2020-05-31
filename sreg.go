/*
Copyright 2020 Howard Liu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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