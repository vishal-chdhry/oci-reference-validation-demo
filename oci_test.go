package main

import "testing"

func Test_ORAS_demo(t *testing.T) {
	ORAS_demo()
}

func Test_RegClient_demo(t *testing.T) {
	certificate := `-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgICALowDQYJKoZIhvcNAQELBQAwUjELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZOb3Rhcnkx
EzARBgNVBAMTCnJlZ2N0bC1uZXcwHhcNMjMwMzMxMTgwMjIwWhcNMjMwNDAxMTgw
MjIwWjBSMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1NlYXR0
bGUxDzANBgNVBAoTBk5vdGFyeTETMBEGA1UEAxMKcmVnY3RsLW5ldzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAPAXkGP+ZO1EW1tAGU/TicaSZUjHlinw
hCwoHjcqHMzWZ2j9mgxcZF43MDQHpAqmJ9uDxz4nnf8Y1PhEcva5nI029AVIY6Fk
a6ayEOKBeiJMj6nklA7snbqTgBQPxbr91W1dgKvkeMjxnAMCAi3o1m0FyreUbuBE
qQr0eFRZI2QwJqESNHd28Me75B97vlvNtKJLnvOpP0NESlP15XdrYI4PiDvZ7zJX
1Kc+qkMw4sXqUaU0FbHmPJMIC3jvjYQ1xrfrKUvfmnK81bLLqdQddMi9YBuuKPcR
ABdSPCqrYIMFwgPK89OgalvyGSMqazyaIqODDI/NPAuvKnA7vYBxoncCAwEAAaMn
MCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3
DQEBCwUAA4IBAQBBPc4aEkCZuaO5eZicA9m3W6neiQBq7VLMbAKs0I3RI8r53mEC
Sx9ScOP+UuCew9RurUPiXWdgzH1qjdHPM87G2RzWrgR+mkVAB49w1kBYlJq0cDvY
L1yf7gtui4kz6mySOio+DL3Y0NZY3DBAnUnfHmxcD6vLTlNIyIifrPIRF9aKvT7+
PhT2KOJuS/RoHl8oQb5Cc0dsOKdujPSCb4nX0Q66O9SXTuF8l3Fp5gEZTiCCBmpn
18GOldVTToD24LlGN/LdFDi6vBrSt/LrvYuLsS2MRqp4rrsPNIPtGm8RhLDE1Tng
geMWx90s1gkG8d9w7jVsuOmcT/p3xhdD0SZ/
-----END CERTIFICATE-----
`

	repo_name := "localhost:5000/lachie/net-monitor:v1"

	artifact_type := "application/vnd.cyclonedx+json"
	RegClient_Demo(repo_name, certificate, artifact_type)
}
