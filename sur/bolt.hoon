/-  bc=bitcoin
|%
+$  witness
  [sig1=hexb:bc sig2=hexb:bc]
+$  pubkey  hexb:bc
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
      first-per-commitment-point=point
  --
::
+$  htlc
  $:  hash=hexb:bc
      delay=blocks
  --
::
+$  commit-tx
  $:  locktime=hexb:bc
      sequence=hexb:bc
      =witness

  --
::  chan: channel state
::
+$  chan
  $:  =funding=txid:bc
      outpoint=[=txid:bc pos=@ud]
      pubkeys=[pubkey pubkey]                 ::  in lexographic order
      funding=sats:bc
      dust-limit=sats:bc
      max-htlc-value-in-flight=msats
      channel-reserve=sats
      htlc-minimum=msats
      feerate-per-kw=sats
      to-self-delay=blocks
      cltv-expiry-delta=blocks
      max-accepted-htlcs=@ud
      our=chlen
      her=chlen
      ::  list of commit txs
      ::    indexed by...txid?  Can loop through all txs on each new block
  --
--
