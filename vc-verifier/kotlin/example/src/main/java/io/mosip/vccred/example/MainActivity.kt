package io.mosip.vccred.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import io.mosip.vccred.example.ui.theme.VcverifierTheme
import io.mosip.vercred.vcverifier.CredentialsVerifier
import io.mosip.vercred.vcverifier.VerificationResult

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            VcverifierTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Greeting(
                        name = "Android",
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}
@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    val verificationResult = remember { mutableStateOf<VerificationResult?>(null) }

    Column(modifier = Modifier.padding(30.dp)) {
        Button(
            onClick = {
                verificationResult.value = verifyVc()
            },
            modifier = Modifier
                .padding(16.dp)
                .height(80.dp)
                .fillMaxWidth()
        ) {


            Text(
                text = "Verify VC",
                modifier = modifier
            )
        }
        Row {

            Image(
                painter = painterResource(
                    id = if (verificationResult.value?.verificationStatus == true) {
                        R.drawable.success
                    } else if(verificationResult.value?.verificationStatus == false){
                        R.drawable.error
                    } else {
                        R.drawable.pending
                    }
                ),
                contentDescription = null,
                modifier = Modifier.size(80.dp)
            )
            Text(
                text = verificationResult.value?.verificationErrorMessage ?: "Status: Waiting...",
                modifier = modifier.fillMaxWidth(),
                maxLines = 5,
                overflow = TextOverflow.Ellipsis
            )

        }
    }
}


fun verifyVc(): VerificationResult{
    val credentialsVerifier = CredentialsVerifier()
    return credentialsVerifier.verifyCredentials(mosipVc)
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    VcverifierTheme {
        Greeting("Android")
    }
}

val mosipVc = """
    {
    "credential": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://apisip-ida-context.json",
            {
                "sec": "https://w3id.org/security#"
            }
        ],
        "credentialSubject": {
            "VID": "65327817407",
            "face": "data:image/jpeg;base64,/9",
            "gender": [
                {
                    "language": "eng",
                    "value": "MLE"
                }
            ],
            "phone": "+++7765837077",
            "city": [
                {
                    "language": "eng",
                    "value": "TEST_CITYeng"
                }
            ],
            "fullName": [
                {
                    "language": "eng",
                    "value": "TEST_FULLNAMEeng"
                }
            ],
            "addressLine1": [
                {
                    "language": "eng",
                    "value": "TEST_ADDRESSLINE1eng"
                }
            ],
            "dateOfBirth": "1992/04/15",
            "id": "invalid-uri",
            "email": "mosipuser123@mailinator.com"
        },
        "id": "https://ida.m8-486a-9d60-fdda68a3ea68",
        "issuanceDate": "2024-09-02T17:36:13.644Z",
        "expirationDate": "2034-09-02T17:36:13.644Z",
        "issuer": "https://apn/ida-controller.json",
        "proof": {
            "created": "2024-09-02T17:36:13Z",
            "jws": "eyJiNj",
            "proofPurpose": "assertionMethod",
            "type": "RsaSignature2018",
            "verificationMethod": "https://apy.json"
        },
        "type": [
            "VerifiableCredential",
            "MOSIPVerifiableCredential"
        ]
    }
}


""".trimIndent()