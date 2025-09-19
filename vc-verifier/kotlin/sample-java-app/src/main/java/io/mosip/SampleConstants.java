package io.mosip;

public class SampleConstants {
    public static final String SAMPLE_FARMER_VC ="""
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://jainhitesh9998.github.io/tempfiles/farmer-credential.json",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ],
      "credentialSubject": {
        "id": "did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiIyd2Q2aHhXaUZDWDlVYnRwbV8td0didjc2dlpoaGRGb3luUTNlQWhaT0prVDlpeWpHOFpjUUtyTFhfY012dkhlYXpPeE1lODZTNnJzS0VLdGdVVWNxOHpnRUZJTG9Pamt2U3VPbFhyNk4yX1E5Y0pFZlVBeVVaN2FTZl9xbEhUTm54Szdld3hyUWRadTRDMGR1MXBWWGdKeDgxeG1TX0RvbUZMUzhiMFFLNjBacXhpVlIweEdEZkVrWnk2RjkzVDBnNVlSREpPVndOeTVxWUdrc05iU2Y1TV95STJzVlROdExjTExxekxKSTdhUjRySlZlOTZJNlU3UGJpTkE0RTl6bzJNcERPWWtXYmxPQlhfeXV1Mjd6U0dFRUEyVC1yUlRhTTh0RWJzWF91TDVJSHZ5Y3VLODdjNlBjSVVXekVuNERCOVdpNU1wY3BPbVRQUWtpMVpacXcifQ==",
        "dob": "1980-01-24",
        "email": "ramesh@mosip.io",
        "gender": "Male",
        "mobile": "9840298402",
        "benefits": [
          "Wheat",
          "Corn"
        ],
        "fullName": "Ramesh",
        "policyName": "Owned",
        "policyNumber": "7550-166-913",
        "policyIssuedOn": "2024-09-18",
        "policyExpiresOn": "2033-04-20"
      },
      "expirationDate": "2024-12-13T11:54:01.352Z",
      "id": "did:rcw:66977a22-c7f9-4ce2-af84-7472c05c80e2",
      "issuanceDate": "2024-11-13T11:54:01.374Z",
      "issuer": "did:web:api.collab.mosip.net:identity-service:a2940bcd-497a-42d4-bec9-3547b41a351e",
      "proof": {
        "type": "Ed25519Signature2020",
        "created": "2024-11-13T11:54:01Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:web:api.collab.mosip.net:identity-service:a2940bcd-497a-42d4-bec9-3547b41a351e#key-0",
        "proofValue": "z3q8eQujAQTV6gRtXg4s9z129GnAXj6HsVfWiKL11WkLWQqtsqUQeZuyDHXNSEunV84jReuLLCxxCgVs11EANWsw6"
      },
      "type": [
        "VerifiableCredential",
        "FarmerCredential"
      ]
    }
""";
}
