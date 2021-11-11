%%%
title = "OpenID Connect for Verifiable Credential Issuance"
abbrev = "openid-4-vc-issuance"
ipr = "none"
workgroup = "connect"
keyword = ["security", "openid", "ssi"]

[seriesInfo]
name = "Internet-Draft"
value = "openid-connect-4-verifiable-credential-issuance-1_0-00"
status = "standard"

[[author]]
initials="T."
surname="Lodderstedt"
fullname="Torsten Lodderstedt"
organization="yes.com"
    [author.address]
    email = "torsten@lodderstedt.net"

[[author]]
initials="K."
surname="Yasuda"
fullname="Kristina Yasuda"
organization="Microsoft"
    [author.address]
    email = "kristina.yasuda@microsoft.com"

%%%

.# Abstract

This specification defines an extension of OpenID Connect to allow holders to request issuance of verifiable credentials in addition to the standard OpenID Connect assertions.

{mainmatter}

# Introduction

This specification extends OpenID Connect with support for issuance of verifiable credentials, e.g. in the form of W3C Verifiable Credentials. This allows existing OpenID Connect OPs to extends their service and become credential issuers. It also allows new applications built using Verifiable Credentials to utilize OpenID Connect as integration and interoperability layer between credential holders and issuers. 

OpenID Connect is an obvious choice for this use case since it already allows Relying Parties to request identity assertions. Verifiable Credentials are very similar in that they allow an Issuer to assert End-User claims. In contrast to the identity assertions, a verifiable credential follows a pre-defined schema (the credential type) and is bound to a key material allowing the holder to prove the legitimate possession of the credential. This allows direct presentation of the credential without involvment of the credential issuer. This specification caters for those differences. 

# Terminology

Credential

A set of one or more claims made by an issuer. (see [@VC_DATA]) Note that this definition differs from that in [OpenID].

Verifiable Credential (VC)

A verifiable credential is a tamper-evident credential that has authorship that can be cryptographically verified. Verifiable credentials can be used to build verifiable presentations, which can also be cryptographically verified. (see [@VC_DATA])

Presentation

Data derived from one or more verifiable credentials, issued by one or more issuers, that is shared with a specific verifier. (see [@VC_DATA])

Verified Presentation (VP)

A verifiable presentation is a tamper-evident presentation encoded in such a way that authorship of the data can be trusted after a process of cryptographic verification. Certain types of verifiable presentations might contain data that is synthesized from, but do not contain, the original verifiable credentials (for example, zero-knowledge proofs). (see [@VC_DATA])

W3C Verifiable Credential Objects

Both verifiable credentials and verifiable presentations

Credential Manifests 

A resource format that defines preconditional requirements, Issuer style preferences, and other facets User Agents utilize to help articulate and select the inputs necessary for processing and issuance of a specified credential. (see [DIF.CredentialManifest])

Deferred Credential Issuance

Issuance of a credentials not directly in the response to a credential issuance request, but following a period of time that can be used to perform certain offline business processes.

# Use Cases

## Holder initiated credential issuance

A user comes across an app where she needs to present a credential, e.g. a bank identity credential. She starts the presentation flow at this app and is sent to her wallet (e.g. via SIOP v2 and OpenID Connect 4 Verifiable Presentations). The wallet determines the desired credential type(s) from the request and notifies the user that there is currently no matching credential in the wallet. The wallet now offers the user a list of suitable issuers, which might be based on an issuer list curated by the wallet publisher. The user picks one of those issuers and is sent to the issuer's user experience (web site or app). There the user authenticates and is asked for consent to issue the required credential into her wallet. She consents and is sent back to the wallet, where she is informed that a credential was sucessfully created and stored in the wallet.

## Holder initiated credential issuance (with pre-requisites)

A user comes across an app where she needs to present a credential, e.g. an university diploma. She starts the presentation flow at this app and is sent to her wallet (e.g. via SIOP v2 and OpenID Connect 4 Verifiable Presentations). The wallet determines the desired credential type(s) from the request and notifies the user that there is currently no matching credential in the wallet. The wallet now offers the user a list of suitable issuers, which might be based on an issuer list curated by the wallet publisher. The user picks one of those issuers and is notified that the issuer requires an identity credential as pre-requisite for issuance of the diploma. The wallet also offers to send the existing bank identity credential to the issuer for that puClientose. The user confirms and is sent to the issuer's user experience (web site or app). The issuer evaluates the bank identity credential, looks up the user in its database, finds her diploma and offers to issue a verifiable credential. The user consents and is sent back to the wallet, where she is informed that a diploma verifiable credential was sucessfully created and stored in the wallet. 

## Issuer initiated credential issuance

The user browses her university's home page, searching for a way to obtain a digital diploma. She finds the respective page, which shows a link "request your digital diploma". She clicks on this link and is being sent to her digital wallet. The wallet notifies her that an issuer offered to issue a diploma credential. She confirms this inquiry and is being sent to the university's credential issuance service. She logs in with her university login and is being asked to consent to the creation of a digital diploma. She confirms and is sent back to her wallet. There she is notified of the sucessful creation of the digital diploma.  

## Issuer initiated credential issuance (cross device/ credential retrival only)

The user visits the administration office of her university in order to obtain a digital diploma. The university staff checks her student card and looks up her university diploma in the universitie's IT system. The office staff then starts the issuance process. The user is asked to scan a QR Code in order to retrieve the digital diploma. She scans the code with her smartphone, which automatically starts her wallet, where she is being notified of the offer to create a digital diploma (the verifiable credential). She consents, which causes the wallet to obtain and store the verifiable credential. 

## Issuer initiated credential issuance (with pre-requisites)

The user navigates to her university's webpage to obtain a digital diploma where she is asked to scan a QR Code to start the retrieval process. She scans the code with her smartphone, which automatically starts her wallet, where she is being notified of the pre-requisit to present her digital student card already stored in the wallet in order to receive a digital diploma (the verifiable credential). She consents, which causes the wallet to obtain and store the verifiable credential. 

## Deferred Credential Issuance (Asynchronous Credential Issuance?)

The user wants to obtain a digital criminal record certificate. She starts the journey in her wallet and is sent to the issuer service of the responsible government authority. She logs in with her eID and requests the issuance of the certificate. She is being notified that the issuance of the certificate will take a couple of days due to necessary background checks by the authority. She confirms and is sent back to the wallet. The wallet shows a hint in the credential list indicating that issuance of the digital criminal record certificate is under way. A few days later, she receives an e-Mail from the authority that the certificate was sucessfully issued. She visits her wallet, where she is asked after startup whether she wants to download the certificate. She confirms and the new credential is retrieved and stored in her wallet. 

# Requirements

This section describes the requirements this specification aims to fulfill the use cases described above. 

* Proof of possession of key material
  * Support all kinds of proofs (e.g. signatures, blinded proofs) but also issuance w/o proof
  * Proofs must be protected against replay by using issuer provided nonce (see also https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop#section-8    
  * The proof mechanisms shall be complementary to OAuth/OIDC mechanisms for request signatures, client authentication, and PoP in order to allow for its parallel usage.  
* It shall be possible to request a single credential as well to request multiple credentials in the same request. Examples of the latter include: 
  * credentials containing different claims for the same user (micro/mono credentials) bound to the same key material
  * batch issuance of multiple credentials of the same type bound to different key material (see mDL)
* It shall be possible to issue multiple credentials based on same consent (e.g. different formats and/or keys - did:key followed by did:ebsi) 
* Support for asynchronous issuance of credentials
* User authentication and identification
  * Issuer shall be able to dynamically obtain further data and be able to authenticate the user at their discretion
  * Holder shall be able to pass existing credentials (as presentations) or identity assertions to the issuance flow
    * Assisted flow (utilizing credential manifest)
    * Presentations/assertions must be protected against replay
* It shall be possible to request standard OIDC claims and credentials in the same flow (to implement wallet onboarding, see EBSI/ESSIF onboarding)
* Support for Credential metadata (holder shall be able to determine the types of credential an issuer is able to issue)
* Ensure OP is authoritative for respective credential issuer (OP (OIDC issuer URL) <-> Issuer ID (DID))
* IncoClientorate/utilize existing specs
  * W3C VC HTTP API(?)
  * DIF Credential manifest(?)

# Overview 

This specification defines mechanisms to allow credential holders (acting as OpenID Connec Clients) to request credential issuers (acting as OpenID Connect OPs) to issue Verifiable Credentials via OpenID Connect. 

The following figure shows the overall flow. 

!---
~~~ ascii-art
+--------------+   +-----------+                                         +-------------+
| User         |   |   Wallet  |                                         |   Issuer    |
+--------------+   +-----------+                                         +-------------+
        |                |                                                      |
        |                |                                                      |
        |                |----------                                            |
        |                |          | (1) [opt] obtain credential_manifest      |
        |                |<---------                                            |
        |    interacts   |                                                      |
        |--------------->|  (2) [opt] request presentation nonce                |
        |                |----------------------------------------------------->|
        |                |      presentation nonce                              |
        |                |<-----------------------------------------------------|
        |                |                                                      |
        |                |  (3.1) authorization req (claims, [opt] input, etc. )|
        |                |----------------------------------------------------->|
        |                |                                                      |
    (4) User Login & Consent                                                    |
        |                |  (5) [opt] request additional VCs (OIDC4VP)          |
        |                |<-----------------------------------------------------| 
        |                |      VCs                                             |
        |                |----------------------------------------------------->| 
        |                |                                                      |
        |                |  (3.2) authorization res (code)                      |
        |                |<-----------------------------------------------------|
        |                |                                                      |
        |                |  (6) token req (code)                                |
        |                |----------------------------------------------------->| 
        |                |      access_token, id_token                          |
        |                |<-----------------------------------------------------|    
        |                |                                                      |
        |                |  (7) credential req (access_token, proofs, ...)      |
        |                |----------------------------------------------------->| 
        |                |      credential req (credentials OR acceptance_token)|
        |                |<-----------------------------------------------------|   
        |                |                                                      |
        |                |  (8) [opt] poll_credentials (acceptance_token)       |
        |                |----------------------------------------------------->| 
        |                |      credentials OR not_ready_yet                    |
        |                |<-----------------------------------------------------|          
~~~
!---
Figure: Overall Credential Issuance Flow

This flow is based on OpenID Connect and the code grant type. Use with other grant types, such as CIBA, will be possible as well. 

Starting point is an interaction of the user with her wallet. The user might, for example, 

* want to present a credential and found out there is no suitable credential present in her wallet or
* have visited the web site of a Credential Issuer and wants to obtain a credential from that issuer. 

It is assumed that the wallet has already obtained knowledge about what credentials this particular 
Credential Issuer offers and whether this issuer expects the holder to present existing credentials
as part of the issuance flow. 

(1) (OPTIONAL) obtain `credential_manifest` with an information of which VCs the Issuer can issue, and optionally what kind of input from the user the Issuer requires to issue that credential.

(2) (OPTIONAL) If the issuer expects certain credentials to be presented in the issuance flow (and the wallet contains suitable credentials), the wallet prepares the process by obtaining a nonce from the issuer. This nonce will be used to prevent malicious wallets from being able to replay those presentations. 

(3.1) In this step, the wallet sends an authorization request to the issuer. This request determines
the types of verifiable credentials the wallet (on behalf of the user) wants to obtain. It MAY also
include verifiable presentations if required by the issuer. 
Note: the wallet MAY utilize a pushed authorization request to first send the payload of the authorization request to the issuer and subsequently use the `request_uri` returned by the issuer in the authorization
request. 

(4) The issuer takes over user interface control and interacts with the user. It will authenticate the
user and ask for her consent to issue the requested credentials. The implementation of this step is at
the discretion of the issuer and out of scope of this specification. The issuer might, for example, 
use a local or federated login for that puClientose. It might also utilize verifiable presentations passed 
in the authorization request or call back to the user's wallet to dynamically obtain verifiable presentations.

(5) (OPTIONAL) If the Issuer requires additional credentials not submitted by the user as the input in step 3.1, it can use OIDC4VP to dynamically request the user to present them.

(3.2) The issuer responds with an authorization code to the wallet. 

(6) The wallet exchanges the authorization code for an Access Token and an ID Token.

(7) This Access Token is used to request the issuance of the actual credentials. The types of credentials the wallet wants to obtain have been passed in the authorization request in (3). This request passes the key material the respective credential shall be bound to. If required by the issuer, the wallet also passes a proof of posession for the key material. This proof of posession uses the SHA256 hash of the Access Token as cryptographic nonce. This ensure replay protection of the proofs. Key material can be expressed in a polymoClienthic manner depending on the credential type being requested. 

The Issuer will either directly respond with the credentials or issue an Acceptance Token, which 
is used by the wallet to poll for completion of the issuance process. 

(8) (OPTIONAL) The wallet polls the issuer to obtain the credentials previously requested in 
step (6). The issuer either responds with the credentials or HTTP status code "202" indicating 
that the issuance is not completed yet. 

Note: if the issuer just wants to offer the user to retrieve an pre-existing credential, it can
encode the parameter set of step (6) in a suitable representation and allow the wallet to start 
with step (6). One option would be to encode the data into a QR Code.  

# Flow 1: Simple Issuance Flow Overview (without submission of input VCs)

This section describes how to perform issuance of a credential using the Simple Issuance Flow, when a credential is issued based on the information the Issuer has obtained about the End-user.

In the Simple Issuance Flow, the credential is issued without credentials being submitted by the End-user. 

It is an Authorization Code Flow with the following additions:
- an extended authorization request syntax that allows to request credential types to be issued
- ability to bind issued credential to a proof submitted by the Client
- a newly defined Credential Endpoint from which credentials can be issued
- acceptance_token that allows Deferred Credential Issuance

## Authorization Endpoint

The Authorization Endpoint is used in the same manner as for the Authorization Code Flow, as defined in Section 3.1.2 of [@!OpenID], with the exception of the differences specified in this section. 
 
### Authorization Request

Authentication Requests are made as defined in Section 3.1.2.1 of [@!OpenID], except that it MUST include the `claims` parameter defined in section 5.5 of [@!OpenID] with a new top-level element `credential`. This element contains type and format of a desired credential as defined below:

* `type`
  * REQUIRED. A JSON array of objects. Each object represents a string of a valid URI for a schema of a requested credential
* `format`
  * REQUIRED. A JSON array of strings that representing a format in which credential is requested to be issued. Valid values are `jwt_vc` and `ldp_vc`.

Below is a non-normative example of an authorization request:
```
  GET /authorize?
    response_type=code
    &client_id=s6BhdRkqt3 
    &redirect_uri=https%3A%2F%2Fwallet.example.org%2Fcb
    &scope=openid
    &claims=%7B%22credential%...%2dp_vc%22%7D%7D%5D%7D%7D
    &state=af0ifjsldkj
```

Below is a non-normative example of a `claims` parameter:
```json=
{
    "credential":{
        "type": ["uri":"..."],
        "format": "ldp_vc"
    }
}
```

### Authorization Response

Authentication Responses are made as defined in Section 3.1.2.5 of [@!OpenID].

Below is a non-normative example of
```
HTTP/1.1 302 Found
  Location: https://wallet.example.org/cb?
    code=SplxlOBeZQQYbYS6WxSbIA
    &state=af0ifjsldkj
```

## Token Endpoint

The Token Endpoint is used in the same manner as for the Authorization Code Flow, as defined in Section 3.1.3 of [@!OpenID].

### Token Request

Authentication Requests are made as defined in Section 3.1.3.1 of [@!OpenID].

Below is a non-normative example of a token request:
```
POST /token HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

  grant_type=authorization_code
  &code=SplxlOBeZQQYbYS6WxSbIA
  &redirect_uri=https%3A%2F%2Fwallet.example.org%2Fcb
  
```

### Token Response

Authentication Requests are made as defined in Section 3.1.3.3 of [@!OpenID].

Below is a non-normative example of a token response:
```
HTTP/1.1 200 OK
  Content-Type: application/json
  Cache-Control: no-store
  Pragma: no-cache

  {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
    "token_type": "bearer",
    "expires_in": 86400,
    "id_token": "eyJodHRwOi8vbWF0dHIvdGVuYW50L..3Mz",
  }
```

## Credential Endpoint

The Credential Endpoint performs Issuance of a credential requested by the End-User. This is done by sending the User Agent to the Credential Endpoint with a parameter defined in this section.

Communication with the Credential Endpoint MUST utilize TLS. 

### Credential Request

A Client makes a Credential Request by presenting a proof to which it is requesting the issued credential to be bound to. 

The Client sends the `proof` parameter to the Credential Endpoint using the HTTP POST method.

### `proof` Property

The `proof` property depends on the signature type. At the minimum, the following parameters MUST be included:

* verificationMethod 
  * cryptographically resolvable identifier
* jws  
  * REQUIRED. A signature performed by a key that can be obtained by an identifier in verificationMethod.
* a_hash 
  * REQUIRED. Hash of an access_token obtained in the Token Request. It is required to prevent submitted `proof` property from being replayed by a malicious Client.

Below is a non-normative example of a `proof` parameter:

```json
{
    "verificationMethod": "did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..l9d0YHjcFAH2H4dB9xlWFZQLUpixVCWJk0eOt4CXQe1NXKWZwmhmn9OQp6YxX0a2LffegtYESTCJEoGVXLqWAA",
    "a_hash": "2H4dB9xl-FZQL-pixV-WJk0eOt4CXQ-1NXKW"
}
```

Below is a non-normative example of a credential request:
```
POST /credential HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

  proof=%7B%22type%22:%22...-ace0-9c5210e16c32%22%7D
```

### Credential Response (synchronous flow)

When the Issuer can immideately issue a requested credential and wants to send an issued credential to the Client, the Credential Response MUST return the following parameter:

* credential
  * REQUIRED. An Array of issued credentials.

Below is a non-normative example of a credential response in a synchronous flow of a Simple Issuance Response:

```
HTTP/1.1 200 OK
  Content-Type: application/json
  Cache-Control: no-store
  Pragma: no-cache

  {
    "credential" : [
      "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L" //Base64URL encoded VC
    ]      
  }
```

### Credential Response (deferred flow)

When the Issuer cannot immideately issue a requested credential and wants to send a token that the Client can later use to receive a credential once it is ready, the Credential Response MUST return the following parameter:

* acceptance_token
  * REQUIRED. A string. MUST be a cryptographically random value.

Below is a non-normative example of a credential response in a deferred flow:
```
HTTP/1.1 200 OK
  Content-Type: application/json
  Cache-Control: no-store
  Pragma: no-cache

  {
    "acceptance_token": "8xLOxBtZp8"
 }
```

# Flow 2: Credential Manifest Flow Overview (with submission of input VCs)

This section describes how to perform issuance of a credential using the Credential Manifest Flow, when a credential is issued based on the credentials submitted by the Client.

In the Credential Manifest Flow, the Client needs to pre-obtain the Issuer's Credential Manifest, and the necessary input credentials, if any. This provides the benefit of the Issuer being able to issue a credential without necessarily having information about that user being stored in its database.

It is an Authorization Code Flow with the following additions, in addition to those outlined in a Simple Issuance Flow:
- a mechanism to pre-obtain Credential Manifest
- a mechanism to obtain a presentation nonce to bind credentials being submitted to the Issuer as an input
- 

Note: discuss the benefits

## Set up phase

Prior to initiating the transaction with the Issuer, the Client MUST obtain information about which type of VCs the Issuer can issue, and, optionally, what kind of input the Issuer requires from the Client in the request to issue that credential. 

The Client MUST obtain `credential_manifest` as defined in DIF Credential Manifest [DIF.CredentialManifest].

### Obtaining the Credential Manifest using OpenID Discovery

The Client SHOULD obtain `credential_manifest` using [@!OpenID.Discovery] from a JSON document that the Issuer made available at the path formed by concatenating the string `/.well-known/openid-configuration` to the Issuer's Issuer Identifier. 

This specification defined the following Issuer Metadata:
* `credential_manifest` 
  * **OPTIONAL**. A JSON array containing a list of Credential Manifests. This parameter enables Issuers to pass Credential Manifests in a single , self-contained parameter.

* `credential_manifest_uri` 
  * **OPTIONAL**. A JSON array containing a list of URIs referencing a resouce containing Credential Manifest. This parameter enables Issuers to list Credential Manifests by reference, rather than by value. The scheme used MUST be https. 

Note: may want to remove `https` scheme restriction

Other mechanisms MAY be used to obtain `credential_manifest`.

### Obtaining Credentials required in Credential Manifest

If the obtained Credential Manifest includes `presentation_definition` and requires the Client to present certain credentials in the authorization request, the Client SHOULD obtain those credentials prior to initiating a transaction with this Issuer. Flow 1: Simple Flow defined in this specification MAY be used.

## Nonce Endpoint

The Nonce Endpoint performs Issuance of a presentation nonce requested by the Client. This is done the Clients using the HTTP POST to send Presentation Nonce Request. 

The Client MUST obtain a presentation nonce from the Issuer, when the Client needs to submit certain pre-obtained credentials to the Issuer to meet the requirements in one of the Issuer's Credential Manifests. The Client MUST bind credentials it is submitting to the received presentation nonce. This step is necessary to prevent submitted VCs from being replayed by a malicious Client.

Communication with the Nonce Endpoint MUST utilize TLS. 

### Presentation Nonce Request

Clients MUST use the HTTP POST method to send the Presentation Nonce Request to the Nonce Server. The Request SHOULD not include any parameters.

The Client MUST perform Client Authentication as defined in Section 9 of [@!OpenID].

Below is a non-normative example of a presentation nonce request using `client_secret_basic` Client Authentication:

```
  POST /nonce HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded
    Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
    
```


### Credential Challenge Response

After receiving and validating a valid Presentation Nonce Request from the Client, the Nonce Server returns a successful response that includes a presentation nonce. The response uses the application/json media type.

The following parameter MUST be included in the response:

* p_nonce
  * presentation nonce that the Client MUST include in the presentations when submitting input credentials in the Authorization Request.

Below is a non-normative example of a credential challenge response

```
 HTTP/1.1 200 OK
  Content-Type: application/json;charset=UTF-8
  Cache-Control: no-store
  Pragma: no-cache

  {
    "p_nonce": "fbe22300-57a6-4f08-ace0-9c5210e16c32",
    "expires_in": "3600"
  }
```
## Authorization Endpoint

The Authorization Endpoint is used in the same manner as for the Authorization Code Flow, as defined in Section 3.1.2 of [@!OpenID], with the exception of the differences specified in the Simple Issuance Flow of this document. 

### Authorization Request

Authentication Requests are made as defined in Section 3.1.2.1 of [@!OpenID], except that it MUST include the `claims` parameter defined in section 5.5 of [@!OpenID] with a new top-level element `credential`. This element contains `credential_application`, and optionally `presentation_submission` properties buth as defined in [DIF.CredentialManifest].

Note: If we define that a credential is always included in `credential`, no need for `credential_fulfillment`. If no need for `credential_fulfillment`, no need for `credential_application`. Instead, can simply say input for which `manifest_id`/`type` of a credential you are providing? 
Note: no need for presentation_submission, just array of VPs? Will not be able to do request issuing multiple credentials of the same type for different puClientoses?

Below is a non-normative example of a `claims` parameter with both `credential_application` and `presentation_submission`:

```json=
{
    "credential": {    
      "credential_application": {
        "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        "manifest_id": "WA-DL-CLASS-A",
        "format": {
          "ldp_vc": {
            "proof_type": [
              "JsonWebSignature2020",
              "EcdsaSecp256k1Signature2019"
            ]
          }
        }
      }
   },
     {
      "presentation_submission": {
        "id": "a30e3b91-fb77-4d22-95fa-871689c322e2",
        "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "descriptor_map": [
          {
            "id": "input_1",
            "format": "jwt_vc",
            "path": "$.verifiableCredential[0]"
          }
        ]
      }
    }
}
```

### Authorization Response

As defined in the Simple Issuance Flow, Authentication Responses are made as defined in Section 3.1.2.5 of [@!OpenID].

## Token Endpoint

As defined in the Simple Issuance Flow, The Token Endpoint is used in the same manner as for the Authorization Code Flow, as defined in Section 3.1.3 of [@!OpenID].

### Token Request

As defined in the Simple Issuance Flow, Token Requests are made as defined in Section 3.1.3.1 of [@!OpenID].

### Token Response

As defined in the Simple Issuance Flow, Authentication Requests are made as defined in Section 3.1.3.3 of [@!OpenID].

## Credential Endpoint 

The Credential Endpoint performs Issuance of a credential requested by the End-User as specified in the Simple Issuance Flow of this document.

### Credential Request

A Client makes a Credential Request by presenting a proof to which it is requesting the issued credential to be bound to as specified in the Simple Issuance Flow of this document.

# Credential Response (synchronous flow)

When the Issuer can immideately issue a requested credential and wants to send an issued credential to the Client, the Credential Response MUST include `credential_fulfillment` in a top-level property `credential` defined in Simple Issuance Flow

Below is a non-normative example of a credential response in a synchronous flow in a Credential Manifest Flow:

```
HTTP/1.1 200 OK
  Content-Type: application/json
  Cache-Control: no-store
  Pragma: no-cache

  {
    "credential" : {
      "credential_fulfillment": {
        "id": "a30e3b91-fb77-4d22-95fa-871689c322e2",
        "manifest_id": "WA-DL-CLASS-A",
        "descriptor_map": [
          {
            "id": "driving_license_1",
            "format": "ldp_vc",
            "path": "$.verifiableCredential[0]"
          }
        ]
      },
      "verifiableCredential":{...}
    }
 }
```

# Credential Response (deferred flow)

When the Issuer cannot immideately issue a requested credential and wants to send a token that the Client can later use to receive a credential once it is ready, the Credential Response MUST return the `acceptance_token` as defined in a Simple Issuance Flow:

# Dynamic request (with OR without submission of input VCs)

This section describes how the Issuer can obtain additional credentials from the End-user if the input submitted by the End-user in the authorization request was not sufficient. The flow utilizes [OIDC4VP] to dynamically request additional credentials. The flow can be used with both Simple Issuance Flow and Credential Manifest Flow.

This provides the benefit of the Issuer being able to adhere to the principle of data minimization, for example by including only minimum requirements in the Credentiam Manifest knowing that it can supplement additional information if needed.

# ToDo

- add DIF.CredentialManifest informative reference

{backmatter}

<reference anchor="VC_DATA" target="https://www.w3.org/TR/vc-data-model">
  <front>
    <title>Verifiable Credentials Data Model 1.0</title>
    <author fullname="Manu Sporny">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Grant Noble">
      <organization>ConsenSys</organization>
    </author>
    <author fullname="Dave Longley">
      <organization>Digital Bazaar</organization>
    </author>
    <author fullname="Daniel C. Burnett">
      <organization>ConsenSys</organization>
    </author>
    <author fullname="Brent Zundel">
      <organization>Evernym</organization>
    </author>
    <author fullname="David Chadwick">
      <organization>University of Kent</organization>
    </author>
   <date day="19" month="Nov" year="2019"/>
  </front>
</reference>

<reference anchor="SIOPv2" target="https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html">
  <front>
    <title>Self-Issued OpenID Provider V2</title>
    <author ullname="Kristina Yasuda">
      <organization>Microsoft</organization>
    </author>
    <author fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author fullname="Tobias Looker">
      <organization>Mattr</organization>
    </author>
   <date day="20" month="Jul" year="2021"/>
  </front>
</reference>

<reference anchor="OpenID" target="http://openid.net/specs/openid-connect-core-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0 incoClientorating errata set 1</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Mike Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
      <organization>Google</organization>
    </author>
    <author initials="C." surname="Mortimore" fullname="Chuck Mortimore">
      <organization>Salesforce</organization>
    </author>
   <date day="8" month="Nov" year="2014"/>
  </front>
</reference>

<reference anchor="DIF.PresentationExchange" target="https://identity.foundation/presentation-exchange/spec/v1.0.0/">
        <front>
          <title>Presentation Exchange v1.0.0</title>
		  <author fullname="Daniel Buchner">
            <organization>Microsoft</organization>
          </author>
          <author fullname="Brent Zunde">
            <organization>Evernym</organization>
          </author>
          <author fullname="Martin Riedel">
            <organization>Consensys Mesh</organization>
          </author>
         <date month="Feb" year="2021"/>
        </front>
</reference>

<reference anchor="OpenID.Discovery" target="https://openid.net/specs/openid-connect-discovery-1_0.html">
  <front>
    <title>OpenID Connect Discovery 1.0 incoClientorating errata set 1</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization>NRI</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Ping Identity</organization>
    </author>
    <author initials="B." surname="de Medeiros" fullname="Breno de Medeiros">
      <organization>Google</organization>
    </author>
    <author initials="E." surname="Jay" fullname="Edmund Jay">
      <organization> Illumila </organization>
    </author>
   <date day="8" month="Nov" year="2014"/>
  </front>
</reference>

<reference anchor="OpenID.Registration" target="https://openid.net/specs/openid-connect-registration-1_0.html">
        <front>
          <title>OpenID Connect Dynamic Client Registration 1.0 incoClientorating errata set 1</title>
		  <author fullname="Nat Sakimura">
            <organization>NRI</organization>
          </author>
          <author fullname="John Bradley">
            <organization>Ping Identity</organization>
          </author>
          <author fullname="Mike Jones">
            <organization>Microsoft</organization>
          </author>
          <date day="8" month="Nov" year="2014"/>
        </front>
 </reference>

# IANA Considerations

TBD

# Acknowledgements {#Acknowledgements}

We would like to thank John Bradley, David Waite, and Alen Horvat for their valuable feedback and contributions that helped to evolve this specification.

# Notices

Copyright (c) 2021 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft or Final Specification solely for the puClientoses of (i) developing specifications, and (ii) implementing Implementers Drafts and Final Specifications based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular puClientose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. The OpenID Foundation invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.

# Document History

   [[ To be removed from the final specification ]]

   -00 

   *  initial revision