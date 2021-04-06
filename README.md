# Introduction

Delphi implementation of JWT([JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token)).

# Supported Algorithms

| Algorithm | Status |
|-|:-:|
| none | :+1: |
| HS256 | :+1: |
| HS384 | :+1: |
| HS512 | :+1: |
| **The following algorithms require 3rd party library** |
| ES256 | :+1: |
| ES384 | :+1: |
| ES512 | :+1: |
| ES256K | Coming Soon |
| PS256 | :+1: |
| PS384 | :+1: |
| PS512 | :+1: |
| RS256 | :+1: |
| RS384 | :+1: |
| RS512 | :+1: |

# Third party library

`ES`, `PS` and `RS` algorithms require third party library: [IPWorks Encrypt](https://www.nsoftware.com/ipworks/encrypt/).

# Generate Key Pairs

```bash
# Generate RSA 2048 bits key pair for RS and PS algorithm
$ openssl genrsa -out rs-private.pem 2048
$ openssl rsa -in rs-private.pem -pubout -out rs-public.pem
$ cat rs-*.pem

# Generate EC256 key pair
$ openssl ecparam -genkey -name prime256v1 -noout -out es256-private.pem
$ openssl ec -in es256-private.pem -pubout -out es256-public.pem
$ cat es256-*.pem

# Generate EC384 key pair
$ openssl ecparam -genkey -name secp384r1 -noout -out es384-key-pair.pem
$ openssl ec -in es384-private.pem -pubout -out es384-public.pem
$ cat es384-*.pem

# Generate EC512 key pair
$ openssl ecparam -genkey -name secp521r1 -noout -out es512-key-pair.pem
$ openssl ec -in es512-private.pem -pubout -out es512-public.pem
$ cat es512-*.pem
```

# Base64 URL Encoding

JWT token is encoded with base64, or more precisely - [base64url](https://tools.ietf.org/html/rfc4648#section-5) encoding.  The base64url is similar to base64 encoding except the last 2 encoded characters **+** and **/** is replaced with **-** and **_** respectively.

Delphi's [System.NetEncoding.TBase64Encoding](http://docwiki.embarcadero.com/Libraries/Sydney/en/System.NetEncoding.TBase64Encoding) only perform standard base64 encoding.

A new class `TBase64UrlEncoding` has implemented perform base64url encoding.

# Using `TJWT`

`TJWT` is constructed using custom managed record.  Here is a simple example:

```pascal
begin
  var J: TJWT;
  J.Claims.iss.ValueString := 'joe';
  WriteLn(J.Sign(TAlgType.HS256, 'secret'));
  WriteLn('Valid: ', J.Validate('secret'));
  WriteLn('Invalid: ', J.Validate('SECRET'));
end;
```

And the output:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UifQ.jVFp6sJys73wlxCiSva4f9PsDhk9-CtpWBikYlUiGVY
Valid: TRUE
Invalid: FALSE
```

# Online tools

Some handy tools for JWT token:

1. https://jwt.io/
2. https://dinochiesa.github.io/jwt/
3. http://keytool.online/
