::  bolt.hoon
::  Datatypes to implement Lightning BOLT RFCs.
::
/-  bc=bitcoin
|%
+$  id  @ud
+$  pubkey  hexb:bc
+$  privkey  hexb:bc
+$  witness  hexb:bc
+$  signature  hexb:bc
+$  outpoint  [=txid:bc pos=@ud =sats:bc]
+$  commitment-number  @ud
+$  point  point:secp:crypto
+$  blocks  @ud                               ::  number of blocks
+$  msats  @ud                                ::  millisats
::  chlen: 1 of the 2 members of a channel
::
+$  chlen
  $:  =ship
      funding-pubkey=pubkey
      shutdown-script-pubkey=pubkey
      revocation-basepoint=point
      payment-basepoint=point
      delayed-payment-basepoint=point
      htlc-basepoint=point
      commitment-number=@ud                   ::  starts at 0
      per-commitment-point=point
      next-per-commitment-point=point
  ==
::
+$  htlc
  $:  from=ship
      =channel=id
      =id
      amount-msat=msats
      payment-hash=hexb:bc
      cltv-expiry=blocks
  ==
::
+$  commit-tx
  $:
      =commitment-number
      ::  lexicographically ordered
      ::  increasing CLTV order tiebreaker for identical HTLCs
      ::
      htlcs=(list htlc)
  ==
::  pending offered HTLC that we're waiting for revoke_and_ack on
::
+$  htlc-pend
  $:  =htlc
      prior-txid=txid:bc
      revocation-pubkey=pubkey
  ==
::
+$  htlc-state
  $:  next-offer=id
      next-receive=id
      offer=(unit htlc-pend)
      receive=(unit htlc-pend)
  ==
::  chan: channel state
::
+$  chan
  $:  =id
      our=chlen
      her=chlen
      =funding=outpoint
      =funding=sats:bc
      dust-limit=sats:bc
      max-htlc-value-in-flight=msats
      channel-reserve=sats:bc
      htlc-minimum=msats
      feerate-per-kw=sats:bc
      to-self-delay=blocks
      cltv-expiry-delta=blocks
      max-accepted-htlcs=@ud
      anchor-outputs=?
      our-commit=commit-tx
      her-commit=commit-tx
      revocations=(map txid:bc per-commitment-secret=privkey)
      =htlc-state
  ==
::  msg: BOLT spec messages between peers
::    defined in RFC02
::
++  msg
  |%
  ::  channel messages
  ::
  +$  open-channel
    $:  chain-hash=hexb:bc
        temporary-channel-id=hexb:bc
        =funding=sats:bc
        dust-limit=sats:bc
        max-htlc-value-in-flight=msats
        channel-reserve=sats:bc
        htlc-minimum=msats
        feerate-per-kw=sats:bc
        to-self-delay=blocks
        cltv-expiry-delta=blocks
        max-accepted-htlcs=@ud
        =first-per-commitment=point
        anchor-outputs=?
    ==
  +$  accept-channel  @ud
  +$  funding-created  @ud
  +$  funding-signed  @ud
  +$  funding-locked  @ud
  ::  htlc messages
  ::
  +$  add-signed-htlc
    $:  add=update-add-htlc
        sign=commitment-signed
    ==
  +$  update-add-htlc
    $:  =channel=id
        =htlc=id
    ==
  +$  commitment-signed
    $:  =channel=id
        sig=signature
        num-htlcs=@ud
        htlc-sigs=(list signature)
    ==
  +$  revoke-and-ack
    $:  =channel=id
        =id
        per-commitment-secret=hexb:bc
        next-per-commitment-point=point
    ==
  --
--
