# SURL

Private Short URL with Cloudflare Workers KV.

- Serverless
- API support
- TOTP verify.

[demo](https://dza.vin/)

# [Deploy](doc/deploy.md)

# API

### Request

```js
axios.post('/', {
    data: data,
    totpToken: totpToken
})
```

### Response

`/${token}` or `No permission`

# .
![x](SURL(KV).png)
