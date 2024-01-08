# Verifiable Credential Verifier Tool

## Usage
````
java -jar vc-verifier-tool-<version>.jar <vc-file-path>
````
For example,
````
java -jar vc-verifier-tool-0.0.1-SNAPSHOT.jar vc-sample.json
````
## Output
For success:
````
{"verificationStatus":"success"}
````

For failure:
````
{"verificationStatus":"failed"}
````
