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
++  base58-prefixes
  ^-  (map network [@ @])
  %-  my
  :~  [%main [0 5]]
      [%testnet [111 196]]
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
      fallback-address=(unit address)
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
++  valid-amount
  |=  amt=(unit amount)
  ?|  =(amt ~)
    ?&(=(+.amt %p) =((mod -.amt 10) 0))
    %.y
  ==
::
++  to-hexb
  |=  =bits
  :*  wid=(div wid.bits 8)
      dat=`@ux`(rsh [0 (mod wid.bits 8)] dat.bits)
  ==
::
++  to-bits
  |=  a=@
  ^-  bits
  [wid=(met 0 a) dat=`@ub`a]
::
++  to-bytes
  |=  a=@
  ^-  hexb
  [wid=(met 3 a) dat=`@ux`a]
::
++  tape-to-bits
  |=  =tape
  ^-  bits
  :*  wid=(mul (lent tape) 8)
      dat=`@ub`(swp 3 (crip tape))
  ==
::
++  read-bits
  |=  [n=@ bs=bits]
  [(take:bit n bs) (drop:bit n bs)]
::
++  pad-bits
  |=  [m=@ data=bits]
  ^-  bits
  |-
  ?:  =(0 (mod wid.data m))  data
  %=  $  data
    :*  wid=(add wid.data 1)
        dat=(lsh [0 1] dat.data)
     ==
  ==
::
++  left-pad-bits
  |=  [n=@ud a=bits]
  |-
  ?:  =(0 (mod wid.a n))  a
  $(wid.a (add 1 wid.a))
::
++  bytes-to-bits
  |=  =hexb
  [wid=(mul wid.hexb 8) dat=`@ub`dat.hexb]
::
++  sig-wid  (mul 8 65)
::
++  extract-signature
  |=  =bits
  :-  (cut 3 [0 65] dat.bits)
  :*  wid=(sub wid.bits sig-wid)
      dat=(rsh [0 sig-wid] dat.bits)
  ==
::
++  decode-signature
  |=  sig=@
  =/  v=@  (dis sig 0xff)
  =.  sig  (rsh [3 1] sig)
  =/  s=@  (cut 4 [0 16] sig)
  =/  r=@  (rsh [3 32] sig)
  [v=v r=r s=s]
::
++  recover-pubkey
  =,  secp:crypto
  |=  [sig=signature hrp=tape raw=bits]
  ^-  (unit hexb)
  ?.  (lte v.sig 3)
    ~&  >>>  "%recover-pubkey: invalid recid {<v.sig>}"
    ~
  =/  sigdata=bits  (signed-data hrp raw)
  =/  hash=@        (hash-data sigdata)
  =/  pubk=point:secp256k1
    %+  ecdsa-raw-recover:secp256k1  hash  sig
  %-  some
  [33 (compress-point:secp256k1 pubk)]
::
++  hash-data
  |=  =bits
  ^-  @
  %+  swp  3
  (shay (div wid.bits 8) (swp 3 dat.bits))
::
++  signed-data
  |=  [hrp=tape raw=bits]
  ^-  bits
  %-  cat:bit
  ~[(tape-to-bits hrp) (pad-bits 8 raw)]
::
++  sign-data
  =,  secp:crypto
  |=  [key=hexb hrp=tape data=bits]
  ^-  bits
  =/  sigdata  (signed-data hrp data)
  =/  hash=@   (hash-data sigdata)
  =+  (ecdsa-raw-sign:secp256k1 hash dat.key)
  %-  cat:bit
  :~  data
      [wid=(mul 32 8) dat=r]
      [wid=(mul 32 8) dat=s]
      [wid=8 dat=v]
  ==
::
++  parse-fallback
  |=  [=network f=bits]
  ^-  (unit address)
  ?.  ?|(=(network %main) =(network %testnet))  ~
  =^  wver=bits  f  (read-bits 5 f)
  ?:  =(dat.wver 17)
    %+  bind  (~(get by base58-prefixes) network)
    |=  n=[@ @]
    =/  b=bits
      %-  cat:bit
      ~[[wid=8 dat=`@ub`-.n] f]
    [%base58 `@uc`dat.b]
  ::
  ?:  =(dat.wver 18)
    %+  bind  (~(get by base58-prefixes) network)
    |=  n=[@ @]
    =/  b=bits
      %-  cat:bit
      ~[[wid=8 dat=`@ub`+.n] f]
    [%base58 `@uc`dat.b]
  ::
  ?:  (lte dat.wver 16)
    %+  bind  (~(get by prefixes) network)
    |=  prefix=tape
    =/  enc=cord
      %+  encode-raw:bech32  prefix
      [0v0 (to-atoms:bit 5 f)]
    [%bech32 enc]
  ~
::
++  encode-fallback
  |=  [=network =address]
  ^-  bits
  ?-    -.address
      %bech32
    %-  need
    %+  bind  (decode-raw:bech32 +.address)
    |=  raw=raw-decoded:bech32
    =/  data=bits  (from-atoms:bit 5 data.raw)
    =/  wver=@ud   dat:(read-bits 8 data)
    ~|  "Invalid witness version {<wver>}"
    ?>  (lte wver 16)
    data
  ::
      %base58
    =/  addr=hexb  [21 `@ux`+.address]
    =/  byte=hexb  (take:byt 1 addr)
    =/  wver=@
      ?:  (is-p2pkh network dat.byte)  17
      ?:  (is-p2sh network dat.byte)   18
      ~|("Unknown address for type {<network>}" !!)
    %-  cat:bit
    :~  [wid=5 dat=wver]
        %-  bytes-to-bits
        %+  drop:byt  1
        addr
    ==
  ==
::
++  is-p2pkh
  |=  [n=network c=@]
  ^-  ?
  %-  need
  %+  bind  (~(get by base58-prefixes) n)
  |=  p=[@ @]  =(c -.p)
::
++  is-p2sh
  |=  [n=network c=@]
  ^-  ?
  %-  need
  %+  bind  (~(get by base58-prefixes) n)
  |=  p=[@ @]  =(c +.p)
::
++  tagged
  |=  [t=@tD b=bits]
  ^-  bits
  =/  c=@  (need (charset-to-value:bech32 t))
  =.  b    (pad-bits 5 b)
  %-  cat:bit
  :~  [wid=5 dat=c]
      [wid=5 dat=(div (div wid.b 5) 32)]
      [wid=5 dat=(mod (div wid.b 5) 32)]
      b
  ==
::
++  tagged-bytes
  |=  [tag=@tD bytes=hexb]
  ^-  bits
  %+  tagged  tag
  %-  bytes-to-bits  bytes
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
++  en
  |=  [in=invoice key=hexb]
  |^  ^-  cord
  =/  hrp=tape  (encode-hrp in)
  =/  inv=bits  (encode-invoice in)
  %+  encode-raw:bech32  hrp
  %+  to-atoms:bit  5
  %^    sign-data
      key
    hrp
  inv
  ::
  ++  encode-invoice
    |=  in=invoice
    ^-  bits
    =|  data=bits
    =/  unix=@ud
      %+  div
      %+  sub  timestamp.in  ~1970.1.1
      ~s1
    ::
    =.  data
    %-  cat:bit  ~[data [wid=35 dat=`@ub`unix]]
    ::
    =.  data
    %-  cat:bit
    ~[data (tagged-bytes 'p' payment-hash.in)]
    ::
    =?  data  ?=(^ payment-secret.in)
    %-  cat:bit
    :~  data
      %+  tagged-bytes  's'
      %-  need  payment-secret.in
    ==
    ::
    =?  data  !=(~ route.in)
    %-  cat:bit
    :~  data
      %+  tagged  'r'
      %+  roll  route.in
      |=  [r=route acc=bits]
      %-  cat:bit
      :~  acc
          [wid=264 dat=`@ub`dat.pubkey.r]
          [wid=64 dat=`@ub`short-channel-id.r]
          [wid=32 dat=`@ub`feebase.r]
          [wid=32 dat=`@ub`feerate.r]
          [wid=16 dat=`@ub`cltv-expiry-delta.r]
      ==
    ==
    ::
    =?  data  ?=(^ fallback-address.in)
    %-  cat:bit
    :~  data
      %+  tagged  'f'
      %+  encode-fallback  network.in
      %-  need  fallback-address.in
    ==
    ::
    =.  data
    %-  cat:bit
    :~  data
      %+  tagged  'c'
      %+  left-pad-bits  5
      %-  to-bits  min-final-cltv-expiry.in
    ==
    ::
    =?  data  ?=(^ description.in)
    =/  desc  (need description.in)
    %-  cat:bit
    :~  data
      %+  tagged-bytes  'd'
      %-  to-bytes  (swp 3 desc)
    ==
    ::
    =?  data  !=(~h1 expiry.in)
    %-  cat:bit
    :~  data
      %+  tagged  'x'
      %+  left-pad-bits  5
      %-  to-bits
      (div expiry.in ~s1)
    ==
    ::
    =?  data  ?=(^ description-hash.in)
    %-  cat:bit
    :~  data
      %+  tagged-bytes  'h'
      %-  need  description-hash.in
    ==
    ::
    =?  data  !=(0 wid.pubkey.in)
    %-  cat:bit
    ~[data (tagged-bytes 'n' pubkey.in)]
    ::
    =?  data  !=(0 dat.feature-bits.in)
    %-  cat:bit
    ~[data (tagged '9' feature-bits.in)]
    ::
    data
  ::
  ++  encode-hrp
    |=  =invoice
    |^  ^-  tape
    ;:  weld  "ln"
      %-  network-to-tape  network.invoice
      %-  amount-to-tape   amount.invoice
    ==
    ::
    ++  network-to-tape
      |=  =network
      (need (~(get by prefixes) network))
    ::
    ++  amount-to-tape
      |=  amt=(unit amount)
      %+  fall
      %+  bind  amt
      |=  =amount
      %+  weld
        %+  murn
        %+  scow  %ud  -.amount
        |=(a=@tD ?:(=(a '.') ~ (some a)))
        ::
        %+  fall
        %+  bind  +.amount
        |=  =multiplier
        (scow %tas multiplier)
        ""
      ""
    --
  --
::
++  de
  |=  body=cord
  |^  ^-  (unit invoice)
  %+  biff  (decode-raw:bech32 body)
  |=  raw=raw-decoded:bech32
  =/  =bits  (from-atoms:bit 5 data.raw)
  ?:  (lth wid.bits sig-wid)
    ~&  >>>  '&de: too short to contain a signature'
    ~
  %+  biff  (rust hrp.raw hum)
  |=  [=network amt=(unit amount)]
  ?.  (valid-amount amt)
    ~&  >>>  '&de: invalid amount'
    ~
  =^  sig=@  bits  (extract-signature bits)
  =/  sig-data=^bits  bits
  =|  =invoice
  =:  network.invoice    network
      amount.invoice     amt
      signature.invoice  (decode-signature sig)
      expiry.invoice     ~s3600
      min-final-cltv-expiry.invoice  18
  ==
  =^  date  bits  (read-bits 35 bits)
  =.  timestamp.invoice
    %-  from-unix:chrono:userlib  dat.date
  |-
  ?.  =(0 wid.bits)
  =^  datum  bits  (pull-tagged bits)
  %_  $
    bits     bits
    invoice  (add-tagged invoice datum)
  ==
  ?.  =(0 wid.pubkey.invoice)  (some invoice)
  %+  bind  (recover-pubkey signature.invoice hrp.raw sig-data)
  |=  key=hexb  invoice(pubkey key)
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
      invoice(expiry `@dr`(mul ~s1 dat.data))
    ::
    ?:  =(u.tag 'c')
      invoice(min-final-cltv-expiry `@ud`dat.data)
    ::
    ?:  =(u.tag 'f')
      invoice(fallback-address (parse-fallback network.invoice data))
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
  ++  unknown-tag
    |=  [=invoice tag=@tD =bits]
    invoice(unknown-tags (~(put by unknown-tags.invoice) tag (to-hexb bits)))
  ::
  ++  route-lent  ^~
    %+  add  264
    %+  add  64
    %+  add  32
    %+  add  32
    16
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
  ::  +from-address: BIP173 bech32 address encoding to hex
  ::  https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  ::  expects to drop a leading 5-bit 0 (the witness version)
  ::
  ++  from-address
    |=  body=cord
    ^-  hexb
    ~|  "Invalid bech32 address"
    =/  d=(unit raw-decoded)  (decode-raw body)
    ?>  ?=(^ d)
    =/  bs=bits  (from-atoms:bit 5 data.u.d)
    =/  byt-len=@  (div (sub wid.bs 5) 8)
    ?>  =(5^0b0 (take:bit 5 bs))
    ?>  ?|  =(20 byt-len)
            =(32 byt-len)
        ==
    [byt-len `@ux`dat:(take:bit (mul 8 byt-len) (drop:bit 5 bs))]
  ::  pubkey is the 33 byte ECC compressed public key
  ::
  ++  encode-pubkey
    |=  [=network pubkey=byts]
    ^-  (unit cord)
    ?.  =(33 wid.pubkey)
      ~&  >>>  pubkey
      ~|('pubkey must be a 33 byte ECC compressed public key' !!)
    =/  prefix  (~(get by prefixes) network)
    ?~  prefix  ~
    :-  ~
    %+  encode-raw  u.prefix
    [0v0 (to-atoms:bit 5 [160 `@ub`dat:(hash-160 pubkey)])]
  --
--
