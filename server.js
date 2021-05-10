// mode: javascript

const shipHost = process.env.SHIP_HOST
const shipPort = process.env.SHIP_PORT
const lndDir = process.env.LND_DIR
const lndHost = process.env.LND_HOST
const network = process.env.BTC_NETWORK

const fs = require('fs')
const http = require('http')
const grpc = require('grpc')
const protoLoader = require('@grpc/proto-loader')
const express = require('express')

process.env.GRPC_SSL_CIPHER_SUITES = 'HIGH+ECDSA'

let macaroon = fs.readFileSync(
    `${lndDir}/data/chain/bitcoin/${network}/admin.macaroon`
) .toString('hex');

let loaderOptions = {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneoffs: true
}

let packagedef = protoLoader.loadSync(['rpc.proto', 'router.proto'], loaderOptions)
let rpcpkg = grpc.loadPackageDefinition(packagedef)
let routerrpc = rpcpkg.routerrpc
let lnrpc = rpcpkg.lnrpc

let cert = fs.readFileSync(`${lndDir}/tls.cert`)
let sslCreds = grpc.credentials.createSsl(cert)
let macaroonCreds = grpc.credentials.createFromMetadataGenerator (
    function(args, callback) {
	let metadata = new grpc.Metadata()
	metadata.add('macaroon', macaroon)
	callback(null, metadata)
    }
)
let creds = grpc.credentials.combineChannelCredentials(sslCreds, macaroonCreds)

let lightning = new lnrpc.Lightning(lndHost, creds)
let router = new routerrpc.Router(lndHost, creds)

let makeRequestOptions = (path, data) => {
    let options = {
	rejectUnauthorized: false,
	requestCert: true,
	hostname: shipHost,
	port: shipPort,
	path: path,
	method: 'POST',
	headers: {
	    'Content-Type': 'application/json',
	    'Content-Length': data.length
	}
    }
    return options
}

let serialize = (obj) => {
    let encodeBytes = (obj) => {
	for (let k in obj) {
	    if (Buffer.isBuffer(obj[k])) {
		obj[k] = obj[k].toString('base64')
	    } else if (typeof obj[k] == "object") {
		encodeBytes(obj[k])
	    }
	}
    }
    encodeBytes(obj)
    return JSON.stringify(obj)
}

let chans = lightning.subscribeChannelEvents({})
chans.on('data', data => {
    let body = serialize(data)
    console.log(body)
    let options = makeRequestOptions('/~volt-channels', body)
    let req = http.request(options, res => {
	console.log(`status: ${res.statusCode}`)
	res.on('data', resp => {
	    process.stdout.write(resp)
	})
    })
    req.on('error', error => { console.error(error) })
    req.write(body)
    req.end()
})
chans.on('status', status => { console.log(status) })
chans.on('end', () => {})

let htlc = router.HtlcInterceptor({})
htlc.on('data', data => {
    let body = serialize(body)
    console.log(body)
    let options = makeRequestOptions('~/volt-htlcs', body)
    let req = http.request(options, res => {
	console.log(`status: ${res.statusCode}`)
	res.on('data', data => {
	    let body = JSON.parse(data)
	    htlc.write(body)
	})
    })
    req.on('error', error => { console.error(error) })
    req.write(body)
    req.end()
})
htlc.on('status', status => { console.log(status) })
htlc.on('end', () => {})

// const app = express()
