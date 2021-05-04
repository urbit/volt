// mode: javascript

const shipHost = process.env.SHIP_HOST
const shipPort = process.env.SHIP_PORT
const lndDir = process.env.LND_DIR
const lndPort = process.env.LND_PORT
const network = process.env.BTC_NETWORK

const express = require('express')
const fs = require('fs')
const WebSocket = require('ws')
const http = require('http')

const macaroon = fs.readFileSync(
    `${lndDir}/data/chain/bitcoin/${network}/admin.macaroon`
) .toString('hex');

const sendToShip = (path) => {
    return (body) => {
	let options = {
	    hostname: shipHost,
	    port: shipPort,
	    path: path,
	    method: 'POST',
	    headers: {
		'Content-Type': 'application/json',
		'Content-Length': body.length
	    }
	}
	console.log(body)
	let req = http.request(options, res => {
	    console.log(`status: ${res.statusCode}`)
	    res.on('data', data => {
		process.stdout.write(data)
	    })
	})
	req.on('error', error => { console.error(error) })
	req.write(body)
	req.end()
    }
}

const streamToShip = (lndUrl, shipPath) => {
    let sock = new WebSocket(lndUrl, {
	rejectUnauthorized: false,
	headers: {
	    'Grpc-Metadata-Macaroon': macaroon,
	},
    })
    sock.on('open', () => { console.log(`Connected: ${lndUrl}`) })
    sock.on('error', (err) => { console.error(err) })
    sock.on('message', sendToShip(shipPath))
    return sock
}

const chanUrl = `ws://localhost:${lndPort}/v1/channels/subscribe?method=GET`
const chans = streamToShip (chanUrl, '/~volt-channels')

// const app = express()
