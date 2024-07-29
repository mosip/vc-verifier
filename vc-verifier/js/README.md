# VC-Verifier

## Features

- Given any signed VC, the library verifies the VC for any tampering.


## Installation

- To build and publich the library locally run the command `yarn && yalc publish`

- To run the tests, run the command `npm test`

## APIs

`verifyCredential( credential )`

`credential` - complete Vc in json format 

returns a Promise which will resolve to true or false based on the verification of the VC.


## License
MIT