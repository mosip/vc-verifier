package io.mosip.vercred.vcverifier.credentialverifier.verifier

import android.util.Log
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.vercred.vcverifier.CredentialsVerifier
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.IssuerSignedNamespaces
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.extractFieldValue
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.extractMso
import io.mosip.vercred.vcverifier.exception.InvalidPropertyException
import io.mosip.vercred.vcverifier.exception.LikelyTamperedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.signature.impl.CoseSignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.CborDataItemUtils
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.regex.Matcher
import java.util.regex.Pattern

private const val ISSUING_COUNTRY = "issuing_country"

class MsoMdocVerifier {
    private val tag: String = CredentialsVerifier::class.java.name

    private val util: io.mosip.vercred.vcverifier.utils.Util =
        io.mosip.vercred.vcverifier.utils.Util()

    fun verify(base64EncodedMdoc: String): Boolean {
        try {

            val (docType, issuerSigned) = MsoMdocVerifiableCredential().parse(base64EncodedMdoc)
            /**
             * a) The DS certificate is authenticated.
             * b) The digital signature verifies with the public key provided in the DS certificate.
             * c) The calculated message digests are the same as the message digests stored in the MSO.
             * d) If the mDL Reader retrieved the issuing_country element, it shall be verified that the value of that
             * element matches the countryName element in the subject field within the DS certificate.
             * e) The DocType in the MSO matches the relevant DocType in the “Documents” structure.
             */

            val mobileSecurityObject = issuerSigned.issuerAuth.extractMso()
            return verifyCertificateChain(issuerSigned.issuerAuth!!)
                    && verifyCountryName(issuerSigned.issuerAuth, issuerSigned.namespaces)
                    && verificationOfCoseSignature(issuerSigned.issuerAuth)
                    && verifyValueDigests(issuerSigned.namespaces, mobileSecurityObject)
                    && verifyDocType(mobileSecurityObject, docType)
        } catch (exception: Exception) {
            when (exception) {
                is SignatureVerificationException,
                is LikelyTamperedException,
                is InvalidPropertyException,
                -> throw exception

                else -> {
                    throw UnknownException("Error while doing verification of credential - ${exception.message}")
                }
            }
        }
    }


    private fun verifyCertificateChain(issuerAuth: Array): Boolean {
        //TODO: Validate the certificate chain by getting the trusted root IACA certificate of the Issuing Authority
        return true
    }

    private fun verifyCountryName(
        issuerAuth: DataItem,
        issuerSignedNamespaces: IssuerSignedNamespaces,
    ): Boolean {

        val issuerCertificate: X509Certificate = extractCertificate(issuerAuth)
            ?: throw SignatureVerificationException("certificate chain is empty")
        val subjectDN: String = issuerCertificate.subjectX500Principal.name
        val countryName: String?

        val countryNamePattern = "C=([^,]+)"
        val pattern: Pattern = Pattern.compile(countryNamePattern)
        val matcher: Matcher = pattern.matcher(subjectDN)

        if (matcher.find()) {
            countryName = matcher.group(1)
        } else {
            throw RuntimeException("CN not found in Subject DN of DS certificate")
        }

        val issuingCountry: String = issuerSignedNamespaces.extractFieldValue(ISSUING_COUNTRY)
        if (countryName == null || !issuingCountry.equals(countryName)) {
            throw InvalidPropertyException("Issuing country is not valid in the credential - Mismatch in credential data and DS certificate country name dound")
        }
        return true
    }

    private fun verifyDocType(mso: Map, docTypeInDocuments: DataItem?): Boolean {
        val docTypeInMso = mso["docType"]
        if (docTypeInDocuments == null) {
            Log.e(
                tag,
                "Error while doing docType property verification - docType property not found in the credential"
            )
            throw InvalidPropertyException("Property docType not found in the credential")
        }
        if (docTypeInMso != docTypeInDocuments) {
            Log.e(
                tag,
                "Error while doing docType property verification - Property mismatch with docType in the credential"
            )
            throw InvalidPropertyException("Property mismatch with docType in the credential")
        }
        return true
    }

    private fun verificationOfCoseSignature(issuerAuth: DataItem): Boolean {
        val issuerCertificate: X509Certificate = extractCertificate(issuerAuth)
            ?: throw SignatureVerificationException("Error while doing COSE signature verification - certificate chain is empty")
        val signatureVerifier: SignatureVerifier = CoseSignatureVerifierImpl()
        return signatureVerifier.verify(
            issuerCertificate.publicKey,
            CborDataItemUtils.toByteArray(issuerAuth),
            null,
            null
        )
    }

    private fun extractCertificate(coseSignature: DataItem): X509Certificate? {
        val certificateChain: MutableCollection<DataItem>? =
            ((coseSignature as Array)[1] as Map).values
        val issuerCertificateString: DataItem = if (certificateChain?.size!! > 1) {
            certificateChain.elementAt(0)[1]
        } else if (certificateChain.size == 1) {
            if (certificateChain.elementAt(0).majorType == MajorType.ARRAY) {
                certificateChain.elementAt(0)[1]
            } else {
                certificateChain.elementAt(0)
            }
        } else {
            return null
        }
        return toX509Certificate(issuerCertificateString)
    }

    private fun toX509Certificate(certificateString: DataItem?): X509Certificate {
        val certFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        return certFactory.generateCertificate(ByteArrayInputStream((certificateString as ByteString).bytes)) as X509Certificate
    }

    private fun verifyValueDigests(issuerSignedNamespaces: Map, mso: Map): Boolean {
        issuerSignedNamespaces.keys.forEach { namespace ->
            run {
                val namespaceData: MutableList<DataItem> =
                    ((issuerSignedNamespaces[namespace]) as Array).dataItems
                val calculatedDigests = mutableMapOf<Number, ByteArray>()
                val actualDigests = mutableMapOf<Number, ByteArray>()


                namespaceData.forEach { issuerSignedItem ->
                    val encodedIssuerSignedItem = ByteArrayOutputStream()
                    CborEncoder(encodedIssuerSignedItem).encode(issuerSignedItem)
                    val digestAlgorithm = mso["digestAlgorithm"].toString()
                    val digest =
                        util.calculateDigest(digestAlgorithm, encodedIssuerSignedItem)
                    val decodedIssuerSignedItem =
                        CborDecoder(ByteArrayInputStream((issuerSignedItem as ByteString).bytes)).decode()[0]
                    val digestId: Number =
                        (((decodedIssuerSignedItem as Map)["digestID"]) as UnsignedInteger).value

                    calculatedDigests[digestId] = digest
                }

                val valueDigests: Map =
                    if ((mso["valueDigests"] as Map).keys.toString().contains(("nameSpaces"))) {
                        ((mso["valueDigests"]["nameSpaces"] as Map)[namespace]) as Map
                    } else {
                        ((mso["valueDigests"] as Map)[namespace]) as Map
                    }

                valueDigests.keys.forEach { digestId ->
                    run {
                        val digest: ByteArray = (valueDigests[digestId] as ByteString).bytes
                        actualDigests[(digestId as UnsignedInteger).value] = digest
                    }
                }

                for ((actualDigestId, actualDigest) in actualDigests) {
                    if (!actualDigest.contentEquals(calculatedDigests[actualDigestId])) {
                        Log.e(
                            tag,
                            "Error while doing valueDigests verification - mismatch in digests found"
                        )
                        throw LikelyTamperedException("valueDigests verification failed - mismatch in digests with $actualDigestId")
                    }
                }
            }
        }

        return true
    }

    operator fun DataItem.get(name: String): DataItem {
        check(this.majorType == MajorType.MAP)
        this as Map
        return this.get(UnicodeString(name))
    }

    operator fun DataItem.get(index: Int): DataItem {
        check(this.majorType == MajorType.ARRAY)
        this as Array
        return this.dataItems[index]
    }
}