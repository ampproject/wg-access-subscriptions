# Web content encryption

## Introduction

This concept was primarily designed for [AMP Access](https://github.com/ampproject/amphtml/blob/master/extensions/amp-access/amp-access.md) and [AMP Subscriptions](https://github.com/ampproject/amphtml/blob/master/extensions/amp-subscriptions/amp-subscriptions.md) protocols. However it's relevant and applicable to Web at large.

Some publishers monetize access to their content. Let's call such content — "premium content". It may be sold via different business models including recurring subscriptions, per-article purchases, metering, and so on. If a user has access to a document the "premium content" is immediately displayed, otherwise the "premium content" is hidden and only a "preview" of the document is shown.

The main question is: how the "premium content" is hidden and how it can be shown based on the authorization.

Typically there are two solutions:
 1. Always deliver the "premium content" and show it only if a user is authorized to see it. This is often called the "client-side" method and it has an obvious drawback of the document containing the "premium" content in plain text.
 2. Deliver the "premium content" only when the user's authorization can be verified. This is the "server-side" method.

There are many tradeoffs associated with each of these methods, including security, performance, packaging, distribution, caching, simplicity, content versioning, etc. As we are designing a solution in this space, we'd like to focus on the following key objectives:

1. The protocol should not rely on any user-identifying data.
2. The protocol should shield the "premium content". The vectors to break this protocol should be no more scalable than stealing content itself (e.g. exporting a document in PDF and emailing it).
3. The protocol should be "easy" for publishers to implement. This is subjective, but we'll focus on reducing the number of systems that have to participate in its implementation.
4. The protocol should allow publishers to delegate authorization to other third-party authorizers, assuming they grant such authorizers a permission to do so.
5. The premium content should not be freely crawlable by default, but allow authorized crawling.
6. The protocol should reduce or eliminate version conflicts between "preview" and "premium" sections.
7. As possible, the protocol should facilitate offline mode and support [Web Packaging](https://github.com/WICG/webpackage) concepts.
8. The protocol should have a good performance: minimize client/server round-trips, eliminate additional need for storage, and reduce client/server CPU needs.
9. The protocol should support various business models such as subscribers, metering, and so on.

Additionally, there are some AMP-specific objectives:

10. The protocol should be ideally supported by AMP Caches with minimal effort (or no effort at all). This is also a valid objective for generic CDNs.
11. The protocol should allow validation. I.e. if the strict validation is required, an AMP Cache must be able to get access to the premium sections and confirm that these sections are valid AMP. This is so that "premium" is not used as an escape hatch from "valid".

We considered a number of approaches, including signing authorization payloads, inter-server authorization services, and so on. However, only the "encrypted premium content" concept met all of the objectives stated above. While the encryption could be somewhat intimidating, we believe that this protocol is overall simpler and gives better performance guarantees.

The remainder of this document will focus on the "encrypted premium content" solution.


## Encrypted premium content solution

In this solution, a document always contains both the "preview" and "premium" sections. Thus, the full document is delivered to all consumers (user's browser, Caches/CDNs, indexers) in exactly the same form. But the "premium" content is encrypted with a per-document key. The per-document key itself is encrypted using the internal publisher key and the public keys issued by authorizers. The authorization endpoint must return the decryption key if access is allowed.

Let's consider how this protocol works from the point of view of a publisher, a client (user agent), and a third-party authorizer.

Below are some examples written in JavaScript for browser or server-side Node.js code and corresponding native crypto packages. However, the code in any other language/package would look very similar. Additionally, the naming used in the proposal will likely change in the final protocol.


### Publishing side

To prepare the document, the publisher has to execute the following steps:

1. Create a random key — the "document key".
2. Create a structure that includes the "document key" and the access requirements — the "document crypt".
3. Encrypt the "document crypt" using the publisher's internal key and the supported authorizers' public keys.
4. Output the encrypted "document crypts" in the document's head.
5. Use the "document key" to encrypt the premium sections.
6. Output the content, including the encrypted "premium" sections.

Let's assume that the document encryption is done using [AES-CTR-256](https://tools.ietf.org/html/rfc3686#section-2.1) — it's a simple and strong algorithm that allows streaming. The keys are 256 bit in length.  **Note: in the implemetation in `amp-subscriptions` AES-GCM has replace AES-CTR**

#### /1/ Create a random key — the "document key".

This part is very simple — a strong random value needs to be created each time a document is prepared:

```javascript
const key = crypto.randomBytes(32);  // 256 bit
```

#### /2/ Create a structure that includes the "document key" and the access requirements — the "document crypt".

The "document crypt" includes the generated key and the access requirements. Access requirements packaged with the key are important — this ensures that a lower-access entitlements cannot be used to access higher-level documents.

```javascript
const documentCrypt = {
 requires: 'norcal.com:premium',
 key: key.toString('base64'),
}
```

#### /3/ Encrypt the "document crypt" using the publisher's internal key and public keys issued by third-party authorizers.

Every service that's allowed to read and/or authorize the premium content, including the publisher themselves, should have an encrypted version of the "document crypt" in the document. A 3rd-party service could be a Cache or a paywall service such as SwG.

```javascript
const encryptedKeys = {};
// For each service/authorizer:
const publicKey = keystore.getPublicKey(serviceId);
const encrypted = crypto.publicEncrypt(
   publicKey,
   encode(documentCrypt));
encryptedKeys[serviceId] = encrypted.toString('base64');
```

There could be a variation, where the protocol may require to also output the key identifier ("kid") to better accommodate key rotation, in which case, this would be:

```javascript
encryptedKeys[serviceId] = {
 kid: "34:f2:56",
 crypt: encrypted.toString('base64'),
}
```

---
**Important: non-malleability of document-crypt encryption**

The choice of types of keys and crypto algorithms is important for both internal and authorizers' keys. The non-malleability property of the encrypted document crypt must be ensured. Otherwise, an attacker would be able to manipulate the encrypted blob in attempt to modify the `requires` field which is critical for access verification.

The good news is that many public key algorithms bake in non-malleability. However, this doesn't cover all algorithms. In particular, RSA PKCS1 does not guarantee non-malleability.

Symmetric algorithms also do not typically guarantee non-malleability. Some form of AEAD/EAX/GCM encryption or [key wrapping](https://tools.ietf.org/html/rfc3394) must be used.

See [Malleability](https://en.wikipedia.org/wiki/Malleability_(cryptography)) for more info. Also see the [Tink](https://github.com/google/tink) project and in particular the [HybridEncrypt](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/HybridEncrypt.java).

---

#### /4/ Output the encrypted "document crypts" in the document's head.

The encrypted "document crypts" are output in the document's `<head>` inside a `<script>` tag:

```html
<head>
  ...
  <script type="application/json" keys>{{encryptedKeys}}</script>
</head>
```

For instance, this could look like this:

```html
<script type="application/json" keys>
 {
   "norcal.com": "G3dl4J9pVj9YmnEPJPdCXOMg9O-uErM-Bow-gBSMNR0",
   "google.com": {
     "kid": "b7:51:43:a1:b5:fc:8b:d9",
     "crypt": "xH5aJGDuYnNvWZSfteFitDDsvMTqIiI8NxlZ1V5nw5g"
   },
 }
</script>
```

#### /5/ Use the "document key" to encrypt the premium sections.

We use a predefined AES-CTR-256 algorithm to encrypt the premium sections using the "document key" generated in the step /1/:

```javascript
const iv = Buffer.from(new Uint8Array(16));  // 0-counter
const cipher = crypto.createCipheriv('AES-CTR', key, iv);
const encrypted = crypto.encrypt(section).toString('base64');
```

The output is the encrypted content encoded using base64.

#### /6/ Output the content, including the encrypted premium sections.

The encrypted content is output into the document inside a `<script>` tag(s):

```html
<script type="application/octet-stream" encrypted>
 {{encrypted}}
</script>
```

Thus, an encrypted premium section could look like this:

```html
<section ...>
 <script type="application/octet-stream;base64" encrypted>
    VGhpcyBpcyBhIG5ldyBpZGVhIHByb3Bvc2VkIGJ5I
    G1hbHRldWJsQC4gVGhlIGZ1bGwgZG9jdW1lbnQgd2
    lsbCBiZSBkZWxpdmVyZWQgdG8gQ2FjaGVzIGFuZCB
    0byBjbGllbnRzLiBCdXQgdGhlIHByZW1pdW0gY29u
    ...
 </script>
</section>
```


### Client side

The client side (such as AMP Runtime) is very simple. It can request the authorization and decrypt the document by executing the following steps:

1. Request authorization from an authorizer using the corresponding "document crypt".
2. Decrypt the encrypted premium sections using the received "document key".
3. Merge the decrypted sections into the main document.

#### /1/ Request authorization using the appropriate "document crypt".

A client can send the authorization requests to all authorizers in parallel. Each authorization request must include the corresponding "document crypt":

```javascript
const serviceId = ...;
const encryptedKeys =
   JSON.parse(document.querySelector('script[keys]').textContent);
const cryptString = encryptedKeys[serviceId];
return fetch(serviceUrl + '?crypt=' + encodeURIComponent(cryptString))
   .then(response => response.json())
   .then(json => importKey(json['key']));
```

The result of this call is the "decryption key" if the authorizer grants access. The client can only proceed to the next steps if the "decryption key" is returned.

#### /2/ Decrypt the encrypted premium sections.

Once the "document key" is available, the client can decrypt the premium sections:

```javascript
return crypto.subtle.decrypt(
    {name: 'AES-CTR'},
    key,
    base64ToBytes(encryptedSection)
  )
  .then(buffer =>
      new TextDecoder().decode(new Uint8Array(buffer)));
```

The result of this decryption is the plain HTML fragment containing the "premium" content.

#### /3/ Merge the decrypted sections into the main document.

Simplistically, the "premium" content can be merged into the document like this:

```javascript
premiumSection.innerHTML = decryptedHtml;
```


### Authorizing side

The publisher themselves will want to be able to authorize the premium content. But also, they could allow other services to read and/or authorize content. For instance, it could be:

* A search indexer,
* An AMP Cache or a CDN,
* A 3rd-party paywall service.

Each 3rd-party that wants to participate, would have to publish its public key. If several services belong to the same entity (e.g. Google Search, Google AMP Cache, and Subscribe with Google), they can share the public key for simplicity.

As the "Client side" describes, the authorizer takes the corresponding "document crypt" as a parameter, and executes the following steps:

1. Decrypt the "document crypt".
2. Check the access requirements.
3. Return the "document key".

#### /1/ Decrypt the "document crypt".

The authorizer uses its internal or private key to decrypt the input "document crypt":

```javascript
const cryptString = ...;
const privateKey = ...;
const decrypted = crypto.privateDecrypt(privateKey, cryptString)
   .toString('utf8');
const documentCrypt = JSON.parse(decrypted);
```

As a result, the authorizer obtains the same documentCrypt structure that was prepared by the publisher. E.g.

```javascript
{
  requires: 'norcal.com:premium',
  key: 'aBcDef781-2-4/sjfdi',
}
```

#### /2/ Check the access requirements.

Next, the authorizer must verify that the current user meets the access requirements:

```javascript
if (user.entitlements.satisfy(documentCrypt.requires)) {
 ...
}
```

This part could vary widely based on a publisher's business model or an authorizer's logic. For instance, in the example above, the user must be entitled to the "norcal.com:premium" product to receive access to the embedded key.

#### /3/ Return the "document key".

If the user has the appropriate entitlements, the authorizer will return the embedded key:

```javascript
if (user.entitlements.satisfy(documentCrypt.requires)) {
  response.send(200, JSON.stringify({
      key: documentCrypt.key
    }));
}
```


## Analysis

The "encrypted premium content" protocol responds well against the set objectives:

> The protocol should not rely on any user-identifying data.

This protocol relies on a single decryption key. Critically, this key is created per document, and *not* user-specific. A separate endpoint returns back this key if an authorizer can internally confirm the access requirements.

> The protocol should shield the premium content. The vectors to break this protocol should not be more scalable than stealing content itself (e.g. exporting a document in PDF and emailing it).

The premium content is always in the document, but the only way to read it is to obtain the decryption key. Because each document uses a random key, stealing one key doesn't provide access to any other document. It's easier to steal the whole document (export as PDF and share) than guess the random "document key".

> The protocol should be "easy" for publishers to implement. This is subjective, but we'll focus here on reducing the number of systems that have to participate in its implementation.

The simplicity of this protocol is in the fact that all the work is concentrated in preparing the document that contains "preview" and encrypted "premium" sections. Once such document is created, there's no more work needed to separately authorize crawlers, paywall services, caches, etc.

> The protocol should allow publishers to delegate authorization to other third-party authorizers, assuming they grant such authorizers a permission to do so.

This protocol explicitly allows multiple parties to be sanctioned by the publisher to access the content. To allow a third-party to access the "premium" sections, a publisher only needs to include their "document crypt" in the document.

> The premium content should not be freely crawlable by default, but allow authorized crawling.

The premium content is encrypted. The robots could download a document, but that has a limited value without the "document key".

On the other hand, an authorized crawler can easily extract the decryption "document key" from the document itself using its own public key — there's no need for a special separate protocol to request index-time permission from the publisher with additional security considerations such as reverse DNS lookup, separate passwords, etc.

One negative: if a new crawling partner is added, the previously created content has to be re-generated with the new encrypted key.

> The protocol should reduce the version conflicts as much as possible between the "preview" and "premium" sections.

There are no version conflicts because a document contains both "preview" and "premium" sections that are packaged at the same time.

> As possible, the protocol should facilitate offline mode and support Web Packaging concepts.

Since the document contains both "preview" and "premium" sections, it's a perfect fit for offline and Web Packaging. This concept separates the distribution from authorization.

> The protocol should have a good performance: minimize client/server round-trips, eliminate additional need for storage, and reduce client/server CPU needs.

The only necessary request is "authorization". But this request is currently always necessary and thus does not add an additional cost. Since the premium content is already present, no other document fetches or redirects needed.

On a slightly negative side, the per-document random key requirement precludes clients from being able to cache the authorization responses. However, the authorization caching is rare in practice.

> The protocol should support various business models such as subscribers, metering, and so on.

Both subscribers and metered users are authorized the same way — by asking and receiving the "document key".

> The protocol should be ideally supported by AMP Caches with minimal effort (or not effort at all). This is also a valid objective for generic CDNs.

A Cache only needs to understand this protocol if it has to validate it. In this case, such a Cache has to publish its public key and decrypt the content. A Cache that's not interested in the validation does not need to do anything at all — all the work is done by the client and authorizers.

> The protocol should allow AMP validation. I.e. if the strict validation is required, an AMP Cache must be able to get access to the premium sections and confirm that these sections are valid AMP. This is so that "premium" is not used as an escape hatch from "valid".

A Cache that requires full validation will have to publish its public key and request the publisher to include it in the "encrypted keys" section.


## Conclusion

To paraphrase David Wheeler and Kevlin Henney: "We can solve any problem by introducing an extra level of encryption" ... "except for the problem of too-many-levels-of-encryption".

