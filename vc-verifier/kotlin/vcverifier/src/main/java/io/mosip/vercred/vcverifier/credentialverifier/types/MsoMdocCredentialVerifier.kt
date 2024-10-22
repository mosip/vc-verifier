package io.mosip.vercred.vcverifier.credentialverifier.types

import android.annotation.SuppressLint
import android.os.Build
import android.util.Log
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import io.mosip.vercred.vcverifier.CredentialsVerifier
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.*
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.Map
import com.android.identity.internal.Util
import io.mosip.vercred.vcverifier.credentialverifier.CBORConverter
import io.mosip.vercred.vcverifier.exception.InvalidPropertyException
import io.mosip.vercred.vcverifier.exception.LikelyTamperedException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.StaleDataException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.utils.BuildConfig
import java.util.regex.Matcher
import java.util.regex.Pattern


class MsoMdocCredentialVerifier  {
    private val tag: String = CredentialsVerifier::class.java.name

    private val util: io.mosip.vercred.vcverifier.utils.Util =
        io.mosip.vercred.vcverifier.utils.Util()

     fun verify(base64EncodedMdoc: String): Boolean {
        try {

            val decodedData: ByteArray = try {
                util.decodeFromBase64UrlFormatEncoded(base64EncodedMdoc)
            } catch (exception: Exception) {
                Log.e(
                    tag,
                    "Error occurred while base64 decoding the credential " + exception.message
                )
                throw exception
            }


            val cbors: MutableList<DataItem>
            try {
                cbors = CborDecoder(ByteArrayInputStream(decodedData)).decode()
            } catch (exception: Exception) {
                Log.e(tag, "Error occurred while CBOR decoding the credential " + exception.message)
                throw exception
            }
            val issuerSigned: DataItem
            val documents: Map
            if ((cbors[0] as Map).keys.toString().contains("documents")) {
                documents = (cbors[0]["documents"] as Array).dataItems[0] as Map
                issuerSigned =
                    if (documents.keys.contains(CBORConverter.toDataItem("org.iso.18013.5.1.mDL"))) {
                        (documents["org.iso.18013.5.1.mDL"] as Map)["issuerSigned"]
                    } else {

                        ((cbors[0] as Map)["documents"][0] as Map)["issuerSigned"]
                    }
            } else {
                documents = cbors[0] as Map
                issuerSigned = (documents)["issuerSigned"]
            }
            val issuerAuth: Array = (issuerSigned["issuerAuth"]) as Array
            val decodedPayload: DataItem? =
                CborDecoder.decode((issuerAuth[2] as ByteString).bytes)[0]
            val mso: Map?
            if ((decodedPayload?.majorType ?: MajorType.INVALID) == MajorType.MAP) {
                mso = decodedPayload as Map
            } else if ((decodedPayload?.majorType ?: MajorType.ARRAY) == MajorType.BYTE_STRING) {
                val decodedPayloadLevel2: DataItem? =
                    CborDecoder.decode((decodedPayload as ByteString).bytes)[0]
                mso = decodedPayloadLevel2 as Map
            } else {
                throw RuntimeException("Invalid Issuer Auth")
            }
            /**
             * a) The DS certificate is authenticated.
             * b) The digital signature verifies with the public key provided in the DS certificate.
             * c) The calculated message digests are the same as the message digests stored in the MSO.
             * d) If the mDL Reader retrieved the issuing_country element, it shall be verified that the value of that
             * element matches the countryName element in the subject field within the DS certificate.
             * e) The DocType in the MSO matches the relevant DocType in the “Documents” structure.
             * f) The elements in the ‘ValidityInfo’ structure are verified against the current time stamp
             */

            return verifyCertificateChain(issuerAuth)
                    && verifyCountryName(issuerAuth, issuerSigned)
                    && verificationOfCoseSignature(issuerAuth)
                    && verifyValueDigests(issuerSigned, mso)
                    && verifyDocType(mso, documents)
                    && verifyValidity(issuerSigned, mso)
        } catch (exception: Exception) {
            when (exception) {
                is SignatureVerificationException,
                is LikelyTamperedException,
                is StaleDataException,
                is InvalidPropertyException,
                -> throw exception

                else -> {
                    throw UnknownException("Error while doing verification of credential - ${exception.message}")
                }
            }
        }
    }


    private fun verifyCertificateChain(issuerAuth: DataItem): Boolean {
        //TODO: Validate the certificate chain by getting the trusted root IACA certificate of the Issuing Authority
        return true
    }

    private fun verifyCountryName(issuerAuth: DataItem, issuerSigned: DataItem): Boolean {

        val issuerCertificate: X509Certificate = extractCertificate(issuerAuth)
            ?: throw SignatureVerificationException("certificate chain is empty")
        val subjectDN: String = issuerCertificate.getSubjectX500Principal().getName()
        var countryName: String? = null

        val pattern: Pattern = Pattern.compile("C=([^,]+)")
        val matcher: Matcher = pattern.matcher(subjectDN)

        if (matcher.find()) {
            countryName = matcher.group(1)
        } else {
            throw RuntimeException("CN not found in Subject DN of DS certificate")
        }

        val issuingCountry = extractField(issuerSigned, "issuing_country")
        println("issuing - $issuingCountry, country - $countryName")
        if (!issuingCountry.equals(countryName)) {
            throw InvalidPropertyException("Issuing country is not valid in the credential - Mismatch in credential data and DS certificate country name dound")
        }
        return true
    }

    private fun verifyDocType(mso: Map, document: DataItem): Boolean {
        val docTypeInMso = mso["docType"]
        val docTypeInDocuments: DataItem
        if ((document as Map).keys.toString().contains("docType")) {
            docTypeInDocuments = document["docType"]
        } else {
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

    //TODO: use utility is date past CurrTime
    @SuppressLint("NewApi")
    private fun verifyValidity(issuerSigned: DataItem, mso: Map): Boolean {
        val validityInfo: Map = mso["validityInfo"] as Map
        val validFrom = if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            println("validfrom unform ${validityInfo["validFrom"]}")
            Instant.parse(
                validityInfo["validFrom"].toString()
            )
        } else {
            TODO("VERSION.SDK_INT < O")
        }
        val validUntil = if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            Instant.parse(
                validityInfo["validUntil"].toString()
            )
        } else {
            TODO("VERSION.SDK_INT < O")
        }

        val isCurrentTimeGreaterThanValidFrom = Instant.now() >= validFrom
        val isCurrentTimeLessThanValidUntil = Instant.now() < validUntil
        val isValidUntilGreaterThanValidFrom = validUntil > validFrom
        if (!(isCurrentTimeLessThanValidUntil && isCurrentTimeGreaterThanValidFrom && isValidUntilGreaterThanValidFrom)) {
            Log.e(
                tag,
                "Error while doing validity verification - invalid validUntil / validFrom in the MSO of the credential"
            )
            throw StaleDataException("invalid validUntil / validFrom in the MSO of the credential")
        }
        return true
    }

    private fun extractIssuerSignedNamespaceItem(
        issuerSignedDataItems: Map,
        elementIdentifier: String,
    ): DataItem? {
        issuerSignedDataItems.keys.forEach { namespace ->
            run {
                val issuerSignedNamespacedDataItems = issuerSignedDataItems.get(namespace) as Array
                issuerSignedNamespacedDataItems.dataItems.forEach { dataItem ->
                    run {
                        val decodedDataItem = CborDecoder.decode((dataItem as ByteString).bytes)[0]
                        if (decodedDataItem["elementIdentifier"]
                                .toString() == elementIdentifier
                        ) {
                            return decodedDataItem["elementValue"]
                        }
                    }
                }
            }
        }
        return null
    }

    private fun verificationOfCoseSignature(issuerAuth: DataItem): Boolean {
        val issuerCertificate: X509Certificate = extractCertificate(issuerAuth)
            ?: throw SignatureVerificationException("Error while doing COSE signature verification - certificate chain is empty")
        val publicKey = issuerCertificate.publicKey
        val coseSign1CheckSignature =
            Util.coseSign1CheckSignature(issuerAuth, byteArrayOf(), publicKey!!)
        if (!coseSign1CheckSignature)
            throw SignatureVerificationException("Error while doing COSE signature verification with algorithm - ${issuerCertificate.sigAlgName}")
        return true
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

    private fun verifyValueDigests(issuerSigned: DataItem, mso: Map): Boolean {
        val issuerSignedNamespacedData = issuerSigned["nameSpaces"] as Map
        issuerSignedNamespacedData.keys.forEach { namespace ->
            run {
                val namespaceData: MutableList<DataItem> =
                    ((issuerSignedNamespacedData[namespace]) as Array).dataItems
                val calculatedDigests = mutableMapOf<Number, ByteArray>()
                val actualDigests = mutableMapOf<Number, ByteArray>()


                namespaceData.forEach { issuerSignedItem ->
                    val encodedIssuerSignedItem = ByteArrayOutputStream()
                    CborEncoder(encodedIssuerSignedItem).encode(issuerSignedItem)
                    //TODO: GET THE DIGEST ALGORITHM FROM MSO
                    val digestAlgorithm = "SHA-256"
                    val digest =
                        util.calculateDigest(digestAlgorithm, encodedIssuerSignedItem)
                    val decodedIssuerSignedItem =
                        CborDecoder(ByteArrayInputStream((issuerSignedItem as ByteString).bytes)).decode()[0]
                    val digestId: Number =
                        (((decodedIssuerSignedItem as Map)["digestID"]) as UnsignedInteger).value

                    calculatedDigests[digestId] = digest
                }
                val issuerAuthPayload: DataItem = (issuerSigned["issuerAuth"] as Array)[2]

                CborDecoder(ByteArrayInputStream((issuerAuthPayload as ByteString).bytes)).decode()[0]
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

    private fun extractField(issuerSigned: DataItem, fieldToBeExtracted: String): String {
        val issuerSignedNamespacedData = issuerSigned["nameSpaces"] as Map
        issuerSignedNamespacedData.keys.forEach { namespace ->
            run {
                val namespaceData: MutableList<DataItem> =
                    ((issuerSignedNamespacedData[namespace]) as Array).dataItems

                namespaceData.forEach { issuerSignedItem ->
                    val encodedIssuerSignedItem = ByteArrayOutputStream()
                    CborEncoder(encodedIssuerSignedItem).encode(issuerSignedItem)
                    //TODO: GET THE DIGEST ALGORITHM FROM MSO
                    val digestAlgorithm = "SHA-256"
                    val digest =
                        util.calculateDigest(digestAlgorithm, encodedIssuerSignedItem)
                    val decodedIssuerSignedItem =
                        CborDecoder(ByteArrayInputStream((issuerSignedItem as ByteString).bytes)).decode()[0]
                    println("((decodedIssuerSignedItem as Map)[\"elementIdentifier\"]) as UnicodeString ${((decodedIssuerSignedItem as Map)["elementIdentifier"]).majorType}")
                    println("((decodedIssuerSignedItem as Map)[\"elementIdentifier\"]) as UnicodeString ${((decodedIssuerSignedItem as Map)["elementIdentifier"])}")
                    val elementIdentifier: String =
                        ((decodedIssuerSignedItem["elementIdentifier"]) as UnicodeString).string

                    if (elementIdentifier == fieldToBeExtracted) {
                        return (decodedIssuerSignedItem["elementValue"] as UnicodeString).string
                    }
                }
            }
        }
        return ""
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

