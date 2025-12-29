# @li0ard/mrtd_passive_auth

PoC for Passive Authentication (PA) implementation for eMRTD using [tsemrtd](https://github.com/li0ard/tsemrtd) and [icaopkd](https://github.com/li0ard/icaopkd)

## Installation

```bash
git clone https://github.com/li0ard/passive_auth && cd passive_auth/

[npm | bun] i

# Optional step for Node.js
npm run build
```

## Usage

Before running, you must dump the eMRTD via proxmark3 and download CSCA masterlist from [ICAO website](https://www.icao.int/icao-pkd/icao-master-list)

For Node:
```bash
node dist/index.js <path to dump folder> <path to CSCA masterlist (.ml)>
```

For Bun:
```bash
bun src/index.ts <path to dump folder> <path to CSCA masterlist (.ml)>
```