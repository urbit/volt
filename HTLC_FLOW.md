HTLC Flow
Implemented with only one offer at a time.

## We Offer an HTLC

### Create HTLC
- make new HTLC
- increment `htlc-next-offer-id`
- `offer.htlc-state`
  * add new HTLC
  * store `her-commit` TXID
  * store `her-commit` revocation-pubkey
- sign and add new HTLC to `her-commit`
- sign `her-commit`
- send `commitment-signed`
  * new HTLC
  * all HTLC sigs w/ id
  * `her-commit` witness
  
### Receive revoke_and_ack
Use `offer.htlc-state`
- ?> `per-commitment-secret` produces `revocation-pubkey`
- generate `revoke-privkey`
- add `prior-txid`& `revoke-privkey` to `revocations`
- move `next-per-commitment-point` to `per-commitment-point`
- update `next-per-commitment-point` to one in this msg
**don't delete** `offer.htlc-state`

### Receive commitment_signed
- ?> num-htlcs is num in `our-commit` + 1
- ?> one of the HTLC signatures matches our `offer.htlc-state`
- compute our `next-per-commitment-point`
- send `revoke_and_ack` for `our-commit` with `next-per-commitment-point`
- add `offer.htlc-state` to `our-commit`
- delete `offer.htlc-state`

-------------------------------------------------------------
## We Receive an HTLC

### Receive update_add_htlc & commitment_signed
- ?> HTLC id is `htlc-next-receive-id`
- increment `htlc-next-receive-id`
- add HTLC to `our-commit`
- `receive.htlc-state`
  * add HTLC
  * store `our-commit` TXID
  * store `our-commit` revocation-pubkey
- compute our `next-per-commitment-point`
- send `revoke_and_ack` for `our-commit` with `next-per-commitment-point`

### Receive revoke_and_ack
- Use `offer.htlc-state`
- ?> `per-commitment-secret` produces `revocation-pubkey`
- generate `revoke-privkey`
- add `prior-txid`& `revoke-privkey` to `revocations`
- move `next-per-commitment-point` to `per-commitment-point`
- update `next-per-commitment-point` to one in this msg
- **delete** `receive.htlc-state`

Now can go ahead and pay HTLC or offer to next hop, if applicable.
