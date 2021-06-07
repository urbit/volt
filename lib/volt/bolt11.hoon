::  BOLT 11: Invoice Protocol for Lightning Payments
::  https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md
::
/-  btc=bitcoin
/+  bcu=bitcoin-utils
=,  btc
=,  bcu
|%
+$  network     ?(%main %testnet %signet %regtest)
+$  multiplier  ?(%m %u %n %p)
+$  amount      [@ud (unit multiplier)]
::
++  prefixes
  ^-  (map network tape)
  %-  my
  :~  [%main "bc"]
      [%testnet "tb"]
      [%signet "tbs"]
      [%regtest "bcrt"]
  ==
::
++  networks
  ^-  (map @t network)
  %-  my
  :~  ['bc' %main]
      ['tb' %testnet]
      ['tbs' %signet]
      ['bcrt' %regtest]
  ==
::
+$  signature
  $:  v=@
      r=@
      s=@
  ==
::
+$  invoice
  $:  =network
      timestamp=@da
      payment-hash=hexb
      payment-secret=(unit hexb)
      =signature
      pubkey=hexb
      expiry=@dr
      min-final-cltv-expiry=@ud
      amount=(unit amount)
      description=(unit @t)
      description-hash=(unit hexb)
      unknown-tags=(map @tD hexb)
      fallback-address=(unit hexb)
      route=(list route)
      feature-bits=bits
  ==
::
+$  route
  $:  pubkey=hexb
      short-channel-id=@ud
      feebase=@ud
      feerate=@ud
      cltv-expiry-delta=@ud
  ==
::
::  decode lightning payment request
::
++  de
  |=  body=cord
  |^  ^-  (unit invoice)
  %+  biff  (decode-raw:bech32 body)
  |=  raw=raw-decoded:bech32
  =/  =bits  (from-atoms:bit 5 data.raw)
  =*  signature-lent  (mul 65 8)
  ?:  (lth wid.bits signature-lent)
    ~&  >>>  'too short to contain a signature'
    ~
  %+  biff  (rust hrp.raw hum)
  |=  [=network amt=(unit amount)]
  ?.  (valid-amount amt)
    ~&  >>>  'invalid amount'
    ~
  =/  sig=@  (cut 3 [0 65] dat.bits)
  =|  =invoice
  =:  network.invoice    network
      amount.invoice     amt
      signature.invoice  (decode-signature sig)
      expiry.invoice     ~s3600
      min-final-cltv-expiry.invoice  18
  ==
  =.  bits
    :*  wid=(sub wid.bits signature-lent)
        dat=(rsh [0 signature-lent] dat.bits)
    ==
  ::
  =/  sig-data=^bits  bits
  =^  date  bits  (read-bits 35 bits)
  =.  timestamp.invoice  (from-unix:chrono:userlib dat.date)
  |-
  ?.  =(0 wid.bits)
  =^  datum  bits  (pull-tagged bits)
  %_  $
    bits       bits
    invoice  (add-tagged invoice datum)
  ==
  ::
  %-  some
  ?.  =(0 wid.pubkey.invoice)  invoice
  invoice(pubkey (recover-pubkey signature.invoice hrp.raw sig-data))
  ::
  ++  decode-signature
    |=  sig=@
    =/  v=@  (dis sig 0xff)
    =.  sig  (rsh [3 1] sig)
    =/  s=@
      %+  dis  sig
        0xffff.ffff.ffff.ffff.
          ffff.ffff.ffff.ffff.
          ffff.ffff.ffff.ffff.
          ffff.ffff.ffff.ffff
    =.  sig  (rsh [3 32] sig)
    =/  r=@  sig
    [v=v r=r s=s]
  ::
  ++  recover-pubkey
    =,  secp:crypto
    |=  [sig=signature hrp=tape raw=bits]
    ^-  hexb
    =/  n=@
      %+  sub  8
      %+  mod  wid.raw  8
    =/  msg=bits
      %-  cat:bit
      :~  :*  wid=(mul (lent hrp) 8)
              dat=`@ub`(swp 3 (crip hrp))
          ==
          :*  wid=(add wid.raw n)
              dat=(lsh [0 n] dat.raw)
          ==
      ==
    =/  hash=@
      %+  swp  3
      %-  shay
      :-  (div wid.msg 8)
          (swp 3 dat.msg)
    :-  33
    %-  compress-point:secp256k1
    %+  ecdsa-raw-recover:secp256k1  hash  sig
  ::
  ++  add-tagged
    |=  [=invoice tag=(unit @tD) len=@ud data=bits]
    ^-  ^invoice
    ?~  tag  invoice
    ?:  =(u.tag 'p')
      ?.  =(len 52)
        (unknown-tag invoice u.tag data)
      invoice(payment-hash (to-hexb data))
    ::
    ?:  =(u.tag 's')
      ?.  =(len 52)
        (unknown-tag invoice u.tag data)
      invoice(payment-secret (some (to-hexb data)))
    ::
    ?:  =(u.tag 'd')
      =/  bytes  (to-hexb data)
      =/  desc
        %-  some
        ^-  @t
        %+  swp  3  dat.bytes
      invoice(description desc)
    ::
    ?:  =(u.tag 'h')
      ?.  =(len 52)
        (unknown-tag invoice u.tag data)
      invoice(description-hash (some (to-hexb data)))
    ::
    ?:  =(u.tag 'n')
      ?.  =(len 53)
        (unknown-tag invoice u.tag data)
      invoice(pubkey (to-hexb data))
    ::
    ?:  =(u.tag 'x')
      invoice(expiry `@dr`dat.data)
    ::
    ?:  =(u.tag 'c')
      invoice(min-final-cltv-expiry `@ud`dat.data)
    ::
    ?:  =(u.tag 'f')
      invoice(fallback-address (some (to-hexb data)))
    ::
    ?:  =(u.tag 'r')
      =|  routes=(list route)
      |-
      =|  =route
      ?:  (lth wid.data route-lent)
        invoice(route (flop routes))
      =^  pkey  data  (read-bits 264 data)
      =^  chid  data  (read-bits 64 data)
      =^  febs  data  (read-bits 32 data)
      =^  fert  data  (read-bits 32 data)
      =^  xpry  data  (read-bits 16 data)
      =:  pubkey.route             (to-hexb pkey)
          short-channel-id.route   dat.chid
          feebase.route            dat.febs
          feerate.route            dat.fert
          cltv-expiry-delta.route  dat.xpry
      ==
      $(routes [route routes], data data)
    ::
    ?:  =(u.tag '9')
      invoice(feature-bits data)
    ::
    (unknown-tag invoice u.tag data)
  ::
  ++  pull-tagged
    |=  in=bits
    ^-  [[(unit @tD) @ud bits] bits]
    =^  typ  in  (read-bits 5 in)
    =^  hig  in  (read-bits 5 in)
    =^  low  in  (read-bits 5 in)
    =/  len      (add (mul dat.hig 32) dat.low)
    =^  dta  in  (read-bits (mul len 5) in)
    =/  tag      (value-to-charset:bech32 dat.typ)
    [[tag len dta] in]
  ::
  ++  unknown-tag
    |=  [=invoice tag=@tD =bits]
    invoice(unknown-tags (~(put by unknown-tags.invoice) tag (to-hexb bits)))
  ::
  ++  read-bits
    |=  [n=@ bs=bits]
    [(take:bit n bs) (drop:bit n bs)]
  ::
  ++  to-hexb
    |=  =bits
    :*  wid=(div wid.bits 8)
        dat=`@ux`(rsh [0 (mod wid.bits 8)] dat.bits)
    ==
  ::
  ++  route-lent  ^~
    %+  add  264
    %+  add  64
    %+  add  32
    %+  add  32
    16
  ::
  ++  valid-amount
    |=  amt=(unit amount)
    ?|  =(amt ~)
      ?&(=(+.amt %p) =((mod -.amt 10) 0))
      %.y
    ==
  ::
  ::  human-readable part parsers
  ::
  ++  hum  ;~(pfix pre ;~(plug net ;~(pose ;~((bend) (easy ~) amt) (easy ~))))
  ++  pre  (jest 'ln')
  ++  net
    %+  sear  ~(get by networks)
    ;~  pose
      (jest 'bcrt')
      (jest 'bc')
      (jest 'tbs')
      (jest 'tb')
    ==
  ++  mpy  (cook multiplier (mask "munp"))
  ++  amt
    ;~  plug
      (cook @ud dem)
      (cook (unit multiplier) ;~((bend) (easy ~) mpy))
    ==
  --
::
::  encode lightning payment invoice
::
++  en
  |=  =invoice
  ^-  cord
  'nope'
::
::  need modified bech32 decoder because 90 char length restriction is lifted
::
++  bech32
  |%
  ++  charset  "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  +$  raw-decoded  [hrp=tape data=(list @) checksum=(list @)]
  ::  below is a port of: https://github.com/bitcoinjs/bech32/blob/master/index.js
  ::
  ++  polymod
    |=  values=(list @)
    |^  ^-  @
    =/  gen=(list @ux)
      ~[0x3b6a.57b2 0x2650.8e6d 0x1ea1.19fa 0x3d42.33dd 0x2a14.62b3]
    =/  chk=@  1
    |-  ?~  values  chk
    =/  top  (rsh [0 25] chk)
    =.  chk
      (mix i.values (lsh [0 5] (dis chk 0x1ff.ffff)))
    $(values t.values, chk (update-chk chk top gen))
  ::
    ++  update-chk
      |=  [chk=@ top=@ gen=(list @ux)]
      =/  is  (gulf 0 4)
      |-  ?~  is  chk
      ?:  =(1 (dis 1 (rsh [0 i.is] top)))
        $(is t.is, chk (mix chk (snag i.is gen)))
      $(is t.is)
    --
  ::
  ++  expand-hrp
    |=  hrp=tape
    ^-  (list @)
    =/  front  (turn hrp |=(p=@tD (rsh [0 5] p)))
    =/  back   (turn hrp |=(p=@tD (dis 31 p)))
    (zing ~[front ~[0] back])
  ::
  ++  verify-checksum
    |=  [hrp=tape data-and-checksum=(list @)]
    ^-  ?
    %-  |=(a=@ =(1 a))
    %-  polymod
    (weld (expand-hrp hrp) data-and-checksum)
  ::
  ++  checksum
    |=  [hrp=tape data=(list @)]
    ^-  (list @)
    ::  xor 1 with the polymod
    ::
    =/  pmod=@
      %+  mix  1
      %-  polymod
      (zing ~[(expand-hrp hrp) data (reap 6 0)])
    %+  turn  (gulf 0 5)
    |=(i=@ (dis 31 (rsh [0 (mul 5 (sub 5 i))] pmod)))
  ::
  ++  charset-to-value
    |=  c=@tD
    ^-  (unit @)
    (find ~[c] charset)
  ++  value-to-charset
    |=  value=@
    ^-  (unit @tD)
    ?:  (gth value 31)  ~
    `(snag value charset)
  ::
  ++  is-valid
    |=  [bech=tape last-1-pos=@]  ^-  ?
    ::  to upper or to lower is same as bech
    ?&  ?|(=((cass bech) bech) =((cuss bech) bech))
        (gte last-1-pos 1)
        (lte (add last-1-pos 7) (lent bech))
    ::  (lte (lent bech) 90)
        (levy bech |=(c=@tD (gte c 33)))
        (levy bech |=(c=@tD (lte c 126)))
    ==
  ::  data should be 5bit words
  ::
  ++  encode-raw
    |=  [hrp=tape data=(list @)]
    ^-  cord
    =/  combined=(list @)
      (weld data (checksum hrp data))
    %-  crip
    (zing ~[hrp "1" (tape (murn combined value-to-charset))])
  ::
  ++  decode-raw
    |=  body=cord
    ^-  (unit raw-decoded)
    =/  bech  (cass (trip body))              ::  to lowercase
    =/  pos  (flop (fand "1" bech))
    ?~  pos  ~
    =/  last-1=@  i.pos
    ::  check bech32 validity (not segwit validity or checksum)
    ?.  (is-valid bech last-1)
      ~
    =/  hrp  (scag last-1 bech)
    =/  encoded-data-and-checksum=(list @)
      (slag +(last-1) bech)
    =/  data-and-checksum=(list @)
      %+  murn  encoded-data-and-checksum
      charset-to-value
    ::  ensure all were in CHARSET
    ?.  =((lent encoded-data-and-checksum) (lent data-and-checksum))
      ~
    ?.  (verify-checksum hrp data-and-checksum)
      ~
    =/  checksum-pos  (sub (lent data-and-checksum) 6)
    `[hrp (scag checksum-pos data-and-checksum) (slag checksum-pos data-and-checksum)]
  --
--
