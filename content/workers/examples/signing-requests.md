---
type: example
summary: Verify a signed request using the HMAC and SHA-256 algorithms or
  return a 403.
tags:
  - Security
  - WebCrypto
pcx_content_type: configuration
title: Sign requests
weight: 1001
layout: example
---

{{<Aside type="note">}}

This example Worker makes use of the [Node.js Buffer API](/workers/runtime-apis/nodejs/buffer/), which is available as part of the Worker's runtime [Node.js compatibility mode](/workers/runtime-apis/nodejs/). To run this Worker, you will need to [enable the `nodejs_compat` compatibility flag](/workers/runtime-apis/nodejs/#enable-nodejs-with-workers).
{{</Aside>}}

You can both verify and generate signed requests from within a Worker using the [Web Crypto APIs](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle).

The following Worker will:

- For request URLs beginning with `/generate/`, replace `/generate/` with `/verify/`, sign the resulting path with its timestamp, and return the full, signed URL in the response body.

- For request URLs beginning with `/verify/`, verify the signed URL and allow the request through.

{{<tabs labels="js | ts">}}
{{<tab label="js" default="true">}}

```js
import { Buffer } from "node:buffer";

const encoder = new TextEncoder();

export default {
  /**
   *
   * @param {Request} request
   * @param {{SECRET_DATA: string}} env
   * @returns
   */
  async fetch(request, env) {
    // You will need some secret data to use as a symmetric key. This should be
    // attached to your Worker as an encrypted secret.
    // Refer to https://developers.cloudflare.com/workers/configuration/secrets/
    const secretKeyData = encoder.encode(
      env.SECRET_DATA ?? "my secret symmetric key"
    );

    // Import your secret as a CryptoKey for both 'sign' and 'verify' operations
    const key = await crypto.subtle.importKey(
      "raw",
      secretKeyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );

    const url = new URL(request.url);

    // This is a demonstration Worker that allows unauthenticated access to both
    // /generate and /verify. In a real application you would want to make sure that
    // users could only generate signed URLs when authenticated
    if (url.pathname.startsWith("/generate/")) {
      url.pathname = url.pathname.replace("/generate/", "/verify/");
      // Signed requests expire after one minute. Note that you should choose
      // expiration durations dynamically, depending on, for example, the path or a query
      // parameter.
      const expirationMs = 60000;
      const expiry = Date.now() + expirationMs;

      // This array contains all the data about the request that you want to be able to verify
      // Here we only sign the expiry and the pathname, but often you will want to
      // include more data (for instance, the URL hostname or query parameters)
      const dataToAuthenticate = JSON.stringify([url.pathname, expiry]);

      const mac = await crypto.subtle.sign(
        "HMAC",
        key,
        encoder.encode(dataToAuthenticate)
      );

      // Refer to https://developers.cloudflare.com/workers/runtime-apis/nodejs/
      // for more details on using NodeJS APIs in Workers
      const base64Mac = Buffer.from(mac).toString("base64");

      url.searchParams.set("mac", base64Mac);
      url.searchParams.set("expiry", expiry.toString());

      return new Response(`${url.pathname}${url.search}`);
    } else if (url.pathname.startsWith("/verify/")) {
      // Make sure you have the minimum necessary query parameters.
      if (!url.searchParams.has("mac") || !url.searchParams.has("expiry")) {
        return new Response("Missing query parameter", { status: 403 });
      }

      const expiry = Number(url.searchParams.get("expiry"));

      const dataToAuthenticate = JSON.stringify([url.pathname, expiry]);

      const receivedMac = Buffer.from(url.searchParams.get("mac"), "base64");

      // Use crypto.subtle.verify() to guard against timing attacks. Since HMACs use
      // symmetric keys, you could implement this by calling crypto.subtle.sign() and
      // then doing a string comparison -- this is insecure, as string comparisons
      // bail out on the first mismatch, which leaks information to potential
      // attackers.
      const verified = await crypto.subtle.verify(
        "HMAC",
        key,
        receivedMac,
        encoder.encode(dataToAuthenticate)
      );

      if (!verified) {
        return new Response("Invalid MAC", { status: 403 });
      }

      if (Date.now() > expiry) {
        return new Response(`URL expired at ${new Date(expiry)}`, {
          status: 403,
        });
      }
    }

    return fetch(new URL(url.pathname, "https://example.com"), request);
  },
};
```

{{</tab>}}
{{<tab label="ts">}}

```ts
import { Buffer } from "node:buffer";

const encoder = new TextEncoder();

export default <ExportedHandler<{ SECRET_DATA: string }>>{
  async fetch(request, env) {
    // You will need some secret data to use as a symmetric key. This should be
    // attached to your Worker as an encrypted secret.
    // Refer to https://developers.cloudflare.com/workers/configuration/secrets/
    const secretKeyData = encoder.encode(
      env.SECRET_DATA ?? "my secret symmetric key"
    );

    // Import your secret as a CryptoKey for both 'sign' and 'verify' operations
    const key = await crypto.subtle.importKey(
      "raw",
      secretKeyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );

    const url = new URL(request.url);

    // This is a demonstration Worker that allows unauthenticated access to both
    // /generate and /verify. In a real application you'd want to make sure that
    // users could only generate signed URLs when authenticated
    if (url.pathname.startsWith("/generate/")) {
      url.pathname = url.pathname.replace("/generate/", "/verify/");
      // Signed requests expire after one minute. Note that you should choose
      // expiration durations dynamically, depending on, for example, the path or a query
      // parameter.
      const expirationMs = 60000;
      const expiry = Date.now() + expirationMs;

      // This array contains all the data about the request that you want to be able to verify
      // Here we only sign the expiry and the pathname, but often you'll want to
      // include more data (for instance, the URL hostname or query parameters)
      const dataToAuthenticate = JSON.stringify([url.pathname, expiry]);

      const mac = await crypto.subtle.sign(
        "HMAC",
        key,
        encoder.encode(dataToAuthenticate)
      );

      // Refer to https://developers.cloudflare.com/workers/runtime-apis/nodejs/
      // for more details on using NodeJS APIs in Workers
      const base64Mac = Buffer.from(mac).toString("base64");

      url.searchParams.set("mac", base64Mac);
      url.searchParams.set("expiry", expiry.toString());

      return new Response(`${url.pathname}${url.search}`);
    } else if (url.pathname.startsWith("/verify/")) {
      // Make sure you have the minimum necessary query parameters.
      if (!url.searchParams.has("mac") || !url.searchParams.has("expiry")) {
        return new Response("Missing query parameter", { status: 403 });
      }

      const expiry = Number(url.searchParams.get("expiry"));

      const dataToAuthenticate = JSON.stringify([url.pathname, expiry]);

      const receivedMac = Buffer.from(url.searchParams.get("mac"), "base64");

      // Use crypto.subtle.verify() to guard against timing attacks. Since HMACs use
      // symmetric keys, you could implement this by calling crypto.subtle.sign() and
      // then doing a string comparison -- this is insecure, as string comparisons
      // bail out on the first mismatch, which leaks information to potential
      // attackers.
      const verified = await crypto.subtle.verify(
        "HMAC",
        key,
        receivedMac,
        encoder.encode(dataToAuthenticate)
      );

      if (!verified) {
        return new Response("Invalid MAC", { status: 403 });
      }

      if (Date.now() > expiry) {
        return new Response(`URL expired at ${new Date(expiry)}`, {
          status: 403,
        });
      }
    }

    return fetch(new URL(url.pathname, "https://example.com"), request);
  },
};
```

{{</tab>}}
{{</tabs>}}
