::  bolt.hoon
::  Datatypes to implement Lightning BOLT RFCs.
/-  bc=bitcoin
|%
+$  witness  hexb:bc
+$  id  @ud
+$  pubkey  hexb:bc
+$  revoke-privkey  hexb:bc
+$  point  @                                  ::  scalar to add in ECDSA
+$  blocks  @ud                               ::  number of blocks
+$  msats  @ud                                ::  millisats
::  chlen: 1 of the 2 members of a channel
::
+$  chlen
  $:  funding-pubkey=pubkey
      shutdown-script-pubkey=pubkey
      revocation-basepoint=point
      payment-basepoint=point
      delayed-payment-basepoint=point
      htlc-basepoint=point
      per-commitment-point=point
      next-per-commitment-point=point
  --
::
+$  htlc
  $:  offer=?
      her=ship
      =channel=id
      =id
      amount-msat=msats
      payment-hash=hexb:bc
      cltv-expiry=blocks
      =local=pubkey
      =remote=pubkey
      wit=witness                            ::  signature needed to spend multisig
      :: TODO: figure out which signatures needed
  --
::
+$  commit-tx
  $:  locktime=hexb:bc
      sequence=hexb:bc
      =revocation=pubkey
      wit=(unit witness)
      our-anchor=(unit hexb:bc)
      her-anchor=(unit hexb:bc)
      ::  lexicographically ordered
      ::  increasing CLTV order tiebreaker for identical HTLCs
      ::
      htlcs=(list htlc)
  --
::  pending offered HTLC that we're waiting for revoke_and_ack on
::
+$  htlc-pend
  $:  =htlc
      prior-txid=txid:bc
      revocation-pubkey=pubkey
  --
::
+$  htlc-state
  $:  next-offer=id
      next-receive=id
      offer=(unit htlc-pend)
      receive=(unit htlc-pend)
  --
::
::  chan: channel state
::
+$  chan
  $:  =id
      our=chlen
      her=chlen
      =funding=txid:bc
      outpoint=[=txid:bc pos=@ud]
      funding=sats:bc
      dust-limit=sats:bc
      max-htlc-value-in-flight=msats
      channel-reserve=sats
      htlc-minimum=msats
      feerate-per-kw=sats
      to-self-delay=blocks
      cltv-expiry-delta=blocks
      max-accepted-htlcs=@ud
      our-commit=commit-tx
      her-commit=commit-tx
      revocations=(map txid:bc revoke-privkey)
      =htlc-state
  --
++  msg
  |%
  +$  commitment-signed
    $:  =channel=id
        sig=signature
        num-htlcs=@ud
        htlc-sigs=(list signature)
    --
  +$  revoke-and-ack
    $:  =channel=id
        =id
        per-commitment-secret=hexb:bc
        next-per-commitment-point=point
    --
  +$  update-add-htlc  @ud
  --
--
