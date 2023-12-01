/**
 * Specification
 * https://developer.zuora.com/zephr-docs/zephr-api/zephr-api-tutorials/hmac-request-signing-and-key-pair/
 */

// let CryptoJS = require("crypto-js");
let uuid = require("uuid");

//Prerequisites: key pairs must be stored in Postman environment
let accessKey = pm.environment.get("access_key");
let secretKey = pm.environment.get("secret_key");

/**
 * create Zephr request signature: algorithm must be SHA256 (do not use HMAC-SHA256)
 */
function signRequest(secretKey, body, path, query, method, timestamp, nonce) {
    let hash = CryptoJS.algo.SHA256.create();
    hash.update(secretKey);
    hash.update(body);
    hash.update(path);
    hash.update(query);
    hash.update(method);
    hash.update(timestamp);
    hash.update(nonce);
    let result = hash.finalize();
    return result;
}

/**
 * Create signature by request URL and payload
 */
function createAuthorizationHeader() {
    //collect signature parameters
    //Note: nonce must be unique for each request. APIs may return errors when you reuse a nonce
    let body = pm.request.body.toString();
    let path = pm.request.url.getPath();
    let query = pm.request.url.getQueryString();
    let timestamp = Date.now().toString();
    let nonce = uuid.v4();
    // console.log(`body: ${body}`);
    // console.log(`path: ${path}`);
    // console.log(`query: ${query}`);
    // console.log(`timestamp: ${timestamp}`);
    // console.log(`nonce: ${nonce}`);
    
    let hash = signRequest(secretKey,
        body,
        path,
        query,
        pm.request.method,
        timestamp,
        nonce);
    // console.log(`hash-sha: ${hash}`);

    //Authorization header
    let authHeader = {
        "key": "Authorization",
        "value": `ZEPHR-HMAC-SHA256 ${accessKey}:${timestamp}:${nonce}:${hash}`
    };
    
    return authHeader;
}

//main
let authHeader = createAuthorizationHeader();
pm.request.headers.add(authHeader);
