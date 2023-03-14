## Requirements

- Docker
- ORAS CLI
- Notation CLI
- Go 1.19+

## Setup
1. Setup Environment variables
   ```
   export PORT=5000
   export REGISTRY=localhost:${PORT}
   export REPO=${REGISTRY}/lachie/net-monitor
   export IMAGE=${REPO}:v1
   ```
2. Start a local instance of CNCF container registry
   ```
   docker run -d -p ${PORT}:5000 ghcr.io/oras-project/registry:v1.0.0-rc.4
   ```

3. Add `localhost:5000` to the list of insecure registries
   
   For Mac: 
   ```
   echo '{"insecureRegistries": ["localhost:5000"]}' > /Users/$USER/Library/Application\ Support/notation/config.json
   ```

   For Linux:
   ```
   echo '{"insecureRegistries": ["localhost:5000"]}' > ~/.config/notation/config.json
   ```

4. Build the image and push it to the CNCF container registory
   ```
   docker build -t $IMAGE https://github.com/wabbit-networks/net-monitor.git#main
   docker push $IMAGE
   ```

5. Add key and certificate to sign the image
   - Key
     ```
     cat << EOF > "/Users/$USER/Library/Application Support/notation/localkeys/wabbit-networks.io.key"
     -----BEGIN PRIVATE KEY-----
     MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDN7Z01UxG2D+h2
     HQT3hqR0nlQPs9WW/dcpT5GaSsqupxbikcgKOhP1egohx3+iXDMmleTZ8RVO6pWe
     leWGbp2LpXo/zJ9xl6KWbWnBYYUv5Y0JEDmWioEUNwt8uB/9Az8wLgatODKvTR1E
     5MRCX6yNgD4AO+Q9dG2mBYU82FSsWGOVhcM9BFsctMyf0VCX3xBZeU+ofrWFf0f1
     ID74C6oQimjOQ+q95aEYqW4VZadGiWWrMv9pdDxLuLRHu1aNp85y/troONynv44p
     Hl9wR+KShy2GUSU/izNqIZr72z1Op7VHZU2TZp0APxSvuANQrjn5FCxrp0CZFblT
     u2T97Hl5AgMBAAECggEAF42+FYNS20gmhpv7HXTBCrWxV7pyC7stCQSY2tUDKcbi
     zzdtcf4CmmlDD2oKJz/0ec1bR7JThZs/UcxDXIT6cCaVPQbildOKPTp2hi/pU/kl
     kIvSim19JhrFrZZB0ma0q4YYLWfoJDTlzCN+bzkSO30Xml8/U+glQoAPJU55IN0m
     dpXEudLExmcTCBoLgLjazaXaqvxFpLdxOJvkiC8qLuLcog5L9EhlXhlQG2X6Di52
     5z7Ke4MkNVbLhKQpqP71wU2chaQP/olYMONDLT341gDDJpwOVl2TFj80beg0sD47
     n2GtZX2Px8ebeXefQflXY96mr6lwbRgRsyBogW28oQKBgQD/AIPnfdrX9Ih8/4bS
     MHLU9yP9Bp0l+E1sEiJJ0SWX0DA4zdaVR/ggGrtPPzbtB6aIf3B6aC6l6YRwG9Cc
     zuhdl5ox8uK1lzH6ICwsZAFINzX6giyhC21ueLWwO4xrngL6HYa3+PUD9q8AUsPu
     TKGVRrTKLN2Scs6tXovH63GVjwKBgQDOu+6e1ZU0tHkI5Guz2++G14TZ2ANq6EYl
     pvvem/sHHcFXcxOD0ZQbaIcuP7U8JxlVMHuy03QLB2UkXI9B5uOMK1RXbhORzUwM
     /eZP/cGdOe5ByoWcb9DycGMVMqAl0vftyhBrSKb3qN3VfNBEOh/+rct9E+Oh57Hp
     +GR+Iu7MdwKBgQCGKg48ULJApw7cvVCA7C6ur+0GZmFuJcsOTiguMFUYH9gPOvVo
     i3oX4hik5DyQz1KmRG64aHIKpucgWPIUXqRRAb+GAiWXpxoLYLv9CwzFow7KY4z5
     mlqUIfxt4ZbK1FL6p2hHCTxYPoTqpaEikrz9Hjtml95n+/GTs8fVgqG7LwKBgFb3
     JbU5Yc/PD49XD5uUrJlLtj4xqZZiaYfTS+bkNOBUew2/gfkUw7oX6a3h7OqGBBkb
     ER4z53/wN3LpYPY3G4fOfmddDexqsVBRyn3h4H20be7NNBGP1BT4hCXZqxbePZ+R
     PgDzihFqvw7ct3vL+8OV9qECKeLk5ann7NZG+a+XAoGAedSYpq8q4cEOHVmXfstn
     c5Y96cKOr0S+LvMOte7o1/H31yF40t1qDUEhm00fNI+naOYbyVSRn158FRqymAlR
     sHOrITL3adgfp2nb7Z2vY1SkvWHbSn3XZWCTX9WcRW3FV32YTjGQ5kdwwvTV7rtV
     Set1orWJONX1jRP14OAYCQE=
     -----END PRIVATE KEY-----
     EOF
     ```
   - Certificate
     ```
     cat << EOF > "/Users/$USER/Library/Application Support/notation/localkeys/wabbit-networks.io.crt"
     -----BEGIN CERTIFICATE-----
     MIIDVjCCAj6gAwIBAgIBUjANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEL
     MAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0bGUxDzANBgNVBAoTBk5vdGFyeTEb
     MBkGA1UEAxMSd2FiYml0LW5ldHdvcmtzLmlvMB4XDTIzMDMxMzE4NDkyMVoXDTIz
     MDMxNDE4NDkyMVowWjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQH
     EwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3RhcnkxGzAZBgNVBAMTEndhYmJpdC1uZXR3
     b3Jrcy5pbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM3tnTVTEbYP
     6HYdBPeGpHSeVA+z1Zb91ylPkZpKyq6nFuKRyAo6E/V6CiHHf6JcMyaV5NnxFU7q
     lZ6V5YZunYulej/Mn3GXopZtacFhhS/ljQkQOZaKgRQ3C3y4H/0DPzAuBq04Mq9N
     HUTkxEJfrI2APgA75D10baYFhTzYVKxYY5WFwz0EWxy0zJ/RUJffEFl5T6h+tYV/
     R/UgPvgLqhCKaM5D6r3loRipbhVlp0aJZasy/2l0PEu4tEe7Vo2nznL+2ug43Ke/
     jikeX3BH4pKHLYZRJT+LM2ohmvvbPU6ntUdlTZNmnQA/FK+4A1CuOfkULGunQJkV
     uVO7ZP3seXkCAwEAAaMnMCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
     AQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IBAQAJnuwWHN6mVhr+E7cJAZmfmbYx0i3R
     O8iRdfvoJjKhc+3Il2PJ3v4dxsF5HO/chQDVRoEMRax0p3e/w5hAEf4UlOsrQ3qY
     DHBEwi6Vmiwt43LHZfpQz4DfLYBZ+33JjdPvVW65j/z0cODox3QTMeR3w2JqWudY
     bxDyNE0aN+ppXflkreRIPslnF1fFzWxYUYDO4qkrTWpCmJZGRIX5GAaGMSroq7cr
     /OitWnJfNkTlFg0q9xGZ5RzJv7PYqFbPJ3Fj3Uon77uw/4ypsNYMEEOfkld9s6Xh
     iMxdWnnXVhq8jFmP/mLCT+cVGpB1NXdeEftIuJN+xjWmnRZi/vmGlYlQ
     -----END CERTIFICATE-----
     EOF
     ```
   - Notation `signingkeys.json`
     ```
     cat << EOF > "/Users/$USER/Library/Application Support/notation/signingkeys.json"
     {
      "default": "wabbit-networks.io",
      "keys": [
          {
              "name": "wabbit-networks.io",
              "keyPath": "/Users/$USER/Library/Application Support/notation/localkeys/wabbit-networks.io.key",
              "certPath": "/Users/$USER/Library/Application Support/notation/localkeys/wabbit-networks.io.crt"
          }
      ]
     }
     EOF
     ``` 

6. Sign the image
   ```
   notation sign $IMAGE
   ```

7. List the referrers of a manifest in the remote registry
   ```
   oras discover -o tree $IMAGE
   ```