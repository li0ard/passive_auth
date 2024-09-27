# passive_auth

Example of passive authentication implementation for eMRTD using [tsemrtd](https://github.com/li0ard/tsemrtd)

Verified on [ECDSA](https://habrastorage.org/webt/o5/0v/3c/o50v3cy3ldwj4yolkukpgw2zrm8.png) and [RSA](https://habrastorage.org/webt/ip/px/yv/ippxyvoxn6e-ueo9xzwsqdqh2ck.png) passport.

### Install

> Clone repo

```bash
# via npm
npm i

# via bun
bun i
```

### Usage
Before running, you must dump the eMRTD via proxmark3 or [eCL0WN](http://download.dexlab.nl/eCL0WN_v1.0.6.apk) and download masterlist from [ICAO site](https://icao.int/Security/FAL/PKD/Pages/ICAO-Master-List.aspx)

For Node:
```bash
npm run build

node dist/index.js <path to dump> <path to CSCA masterlist (.ml)>
```

For Bun:
```bash
bun index.ts <path to dump> <path to CSCA masterlist (.ml)>
```
