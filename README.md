# SURL

Short URL (Workers KV)

# Deploy

1. Create a Service ![1](./doc/1.png)
2. Copy the `COPY_THIS.js` to your Workers ![2](./doc/2.png)
3. Add environment variable `SEED:number` `TotpKey:string` ![3](./doc/3.png)
   suggest ![3s](./doc/3s.png)
4. Create namespace![4](./doc/4.png)
5. KV Namespace Bindings![5](./doc/5.png)
6. Custom Domains![6](./doc/6.png)

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