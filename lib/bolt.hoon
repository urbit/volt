::  bolt.hoon
::  Library functions to implement Lightning BOLT RFCs.
::
/-  *bolt
/+  bc=bitcoin, script=bolt-script
|%
++  make-channel-id
  |=  [funding-txid=id funding-output-index=@ud]
  ^-  id
  (mix funding-txid funding-output-index)
::
++  msats-to-sats
  |=  a=msats
  ^-  sats:bc
  (div a 1.000)
::  +bolt-tx
::    helpers for building & signing commitment/HTLC txs
::
++  bolt-tx
  |%
  ++  p2wsh
    |=  s=script:script
    ^-  hexb:bc
    %-  en:script
    :~  %op-0
        :-  %op-pushdata
        %-  sha256:bc  (en:script s)
    ==
  ::  +obscured-commitment-number
  ::    generate obscured commitment number.
  ::
  ++  obscured-commitment-number
    =,  secp256k1:secp:crypto
    |=  [lar=larva-chan cn=commitment-number]
    ~|  "invalid channel state"
    ?<  ?|(?=(~ oc.lar) ?=(~ ac.lar))
    |^  ^-  @ud
    (mix dat:(mask) cn)
    ::
    ++  mask  |.
      ^-  hexb:bc
      %+  drop:byt:bc  26
      %-  sha256:bc
      %-  cat:byt:bc
      :~  [33 (compress-point payment.basepoints.u.oc.lar)]
          [33 (compress-point payment.basepoints.u.ac.lar)]
      ==
    --
  ::
  ++  funding
    |%
    ++  output
      |=  [p1=pubkey p2=pubkey amt=sats:bc]
      ^-  output:tx:bc
      =/  script=hexb:bc
        %-  p2wsh
        %+  output-script  p1  p2
      :*  script-pubkey=script
          value=amt
      ==
    ::
    ++  output-script
      |=  [p1=pubkey p2=pubkey]
      ;:  welp
        ~[%op-2]
        ?:  (lte dat.p1 dat.p2)
          :~  [%op-pushdata p1]
              [%op-pushdata p2]
          ==
        :~  [%op-pushdata p2]
            [%op-pushdata p1]
        ==
        ~[%op-2 %op-checkmultisig]
      ==
    ::
    ++  tx
      |=  $:  lpk=pubkey              ::  local pubkey
              rpk=pubkey              ::  remote pubkey
              amt=sats:bc             ::  funding amount
              ins=(list input:tx:bc)  ::  funding inputs
              chg=output:tx:bc        ::  change output
              ws=(list witness)       ::  input witnesses
          ==
      |^  ^-  data:^tx
      :-  :*  is=ins
              os=outputs
              locktime=0
              nversion=2
              segwit=(some 1)
          ==
          ws=ws
      ::
      ++  outputs
        ^-  (list output:tx:bc)
        %-  sort-outputs:bip69
          ~[(output lpk rpk amt) chg]
      --
    --
  ::
  ++  commitment
    |%
    ::  +input
    ::    generate input from funding-outpoint sequence:
    ::    upper 8 bits are 0x80, lower 24 bits are upper
    ::    24 bits of the obscured commitment number
    ::
    ++  input
      |=  o=outpoint
      ^-  input:tx:bc
      *input:tx:bc
    ::
    ++  remote-output
      |=  $:  =pubkey      ::  remote pubkey
              amt=sats:bc  ::  amt to remote
          ==
      ^-  output:tx:bc
      =/  script=hexb:bc
        %-  p2wsh
        %-  remote-output-script  pubkey
      [script-pubkey=script value=amt]
    ::
    ++  remote-output-script
      |=  =pubkey
      :~  [%op-pushdata pubkey]
          %op-checksigverify
          %op-1
          %op-checksequenceverify
      ==
    ::
    ++  local-output
      |=  $:  rvk=pubkey   ::  revocation pubkey
              ldk=pubkey   ::  local delayed pubkey
              amt=sats:bc  ::  amount to local
          ==
      ^-  output:tx:bc
      =/  script=hexb:bc
        %-  p2wsh
        %+  local-output-script  rvk  ldk
      [script-pubkey=script value=amt]
    ::
    ++  local-output-script
      |=  [rv=pubkey ld=pubkey]
      :~  %op-if
          [%op-pushdata rv]
          %op-else
          %op-checksequenceverify
          %op-drop
          [%op-pushdata ld]
          %op-endif
          %op-checksig
      ==
    ::
    ++  anchor-output
      |=  [=pubkey amt=sats:bc]
      ^-  output:tx:bc
      =/  script=hexb:bc
        %-  p2wsh
        %-  anchor-output-script  pubkey
      [script-pubkey=script value=amt]
    ::
    ++  anchor-output-script
      |=  =pubkey
      :~  [%op-pushdata pubkey]
          %op-checksig
          %op-ifdup
          %op-notif
          %op-16
          %op-checksequenceverify
          %op-endif
      ==
    ::
    ++  tx
      |=  [c=chan our=?]
      |^  ^-  data:^tx
      ::  returns txid and full tx and signature?
      ::  Algo:
      ::  generate HTLC outputs
      ::  nVersion: 02000000
      ::  nLocktime: upper 8 bits are 0x20, lower 24 bits are
      ::  the lower 24 bits of the obscured commitment number
      %-  chlen-tx
      ?:  our
        our.c
      her.c
      ::
      ++  chlen-tx
        |=  =chlen
        ::  offered.commit-state.chlen
        ::  received.commit-state.chlen
        *data:^tx
      --
    --
  ::
  ++  htlc
    |%
    ++  output
      |=  [c=chan our=?]
      |^  ^-  output:tx:bc
      ::  if from=us, do received, else offered
      %.  c
      ?:  our
        received-output
      offered-output
      ::
      ++  offered-output
        |=  c=chan
        =/  =htlc-pend  (need offer.htlc-state.c)
        =/  script=script:script
          %+  offered-script
            c
          htlc-pend
        :*  script-pubkey=(p2wsh script)
            value=(msats-to-sats amount-msat.htlc.htlc-pend)
        ==
      ::
      ++  received-output
        |=  c=chan
        =/  =htlc-pend  (need receive.htlc-state.c)
        =/  script=script:script
          %+  received-script
            c
          htlc-pend
        :*  script-pubkey=(p2wsh script)
            value=(msats-to-sats amount-msat.htlc.htlc-pend)
        ==
      --
    ::
    ++  offered-script
      |=  [c=chan h=htlc-pend]
      :~  %op-dup
          %op-hash160
          [%op-pushdata (hash-160:bc revocation-pubkey.h)]
          %op-equal
          %op-if
          %op-checksig
          %op-else
          [%op-pushdata funding-pubkey.her.c]
          %op-swap
          %op-size
          [%op-pushdata [1 32]]
          %op-equal
          %op-notif
          %op-drop
          %op-2
          %op-swap
          [%op-pushdata funding-pubkey.our.c]
          %op-2
          %op-checkmultisig
          %op-else
          %op-hash160
          [%op-pushdata (hash-160:bc payment-hash.htlc.h)]
          %op-equalverify
          %op-checksig
          %op-endif
          %op-endif
      ==
    ::
    ++  received-script
      |=  [c=chan h=htlc-pend]
      ~
    ::
    ++  timeout-tx
      |=  c=chan
      ^-  data:tx
      *data:tx
    ::
    ++  success-tx
      |=  c=chan
      ^-  data:tx
      *data:tx
    --
  ::
  ++  closing
    |%
    ++  input
      ~
    ::
    ++  output
      ~
    ::
    ++  tx
      |=  c=chan
      ~
    --
  --
::
::  bitcoin-txu
::   wrappers to add functionality to lib/bitcoin.hoon
::   should be ported back and PR'd there when done
::
++  bitcoin-txu
  |%
  ++  sighash
    |%
    +$  value  ?(%all %none %single %anyone-can-pay)
    ::
    ++  en
      |=  s=(set value)
      ^-  @ux
      %-  ~(rep in s)
      |=  [a=value b=@ux]
      %+  con  b
      ?-  a
        %all             0x1
        %none            0x2
        %single          0x3
        %anyone-can-pay  0x80
      ==
    ::
    ++  de
      |=  a=@ux
      ^-  (set value)
      =|  r=(set value)
      =?  r  !=((dis 0x80 a) 0)
        (~(put in r) %anyone-can-pay)
      ?:  =((dis 0x3 a) 0x3)
        (~(put in r) %single)
      ?:  =((dis 0x1 a) 0x1)
        (~(put in r) %all)
      ?:  =((dis 0x2 a) 0x2)
        (~(put in r) %none)
      ~|("invalid sighash" !!)
    --
  ::
  ++  en
    |%
    ++  witness
      |=  w=^witness
      ^-  hexb:bc
      %-  cat:byt:bc
      :-  (en:csiz:bc (lent w))
      %-  zing
      %+  turn  w
      |=  b=hexb:bc  ~[(en:csiz:bc wid.b) b]
    --
  ::
  ++  de
    |%
    ++  witnesses
      |=  $:  b=hexb:bc  ::  tx byte stream
              n=@ud      ::  number of tx inputs
          ==
      ^-  [(list ^witness) rest=hexb:bc]
      =|  acc=(list ^witness)
      |-
      ?:  =(0 n)
        [(flop acc) b]
      =^  w  b  (witness b)
      $(acc [w acc], n (dec n), b b)
    ::
    ++  witness
      |=  b=hexb:bc
      ^-  [^witness rest=hexb:bc]
      =^  n  b  (dea:csiz:bc b)
      =|  acc=^witness
      |-
      ?:  =(0 n)  [(flop acc) b]
      =^  siz  b  (dea:csiz:bc b)
      =^  elt  b
        [(take:byt:bc siz b) (drop:byt:bc siz b)]
      $(acc [elt acc], n (dec n), b b)
    --
  ::
  ++  segwit-encode
    |=  =data:tx
    ^-  hexb:bc
    %-  cat:byt:bc
    %-  zing
    :~  ~[(flip:byt:bc 4^nversion.data)]
        ?:  ?&  ?=(^ segwit.data)
                ?=(^ ws.data)
            ==
          :~  [wid=2 dat=0x1]
          ==
        ~
        ~[(en:csiz:bc (lent is.data))]
        (turn is.data input:en:txu:bc)
        ~[(en:csiz:bc (lent os.data))]
        (turn os.data output:en:txu:bc)
        (turn ws.data witness:en)
        ~[(flip:byt:bc 4^locktime.data)]
    ==
  ::
  ++  segwit-decode
    |=  b=hexb:bc
    ^-  data:tx
    =^  nversion  b
      (nversion:de:txu:bc b)
    =^  segwit  b
      (segwit:de:txu:bc b)
    =^  inputs  b
      (inputs:de:txu:bc b)
    =^  outputs  b
      (outputs:de:txu:bc b)
    =^  witnesses  b
      ?^  segwit
        %+  witnesses:de  b
        %-  lent  inputs
      `b
    =/  locktime=@ud
      dat:(take:byt:bc 4 (flip:byt:bc b))
    [[inputs outputs locktime nversion segwit] witnesses]
  ::
  ++  sign-tx
    |=  [tx=data:tx shash=(set value:sighash) k=hexb:bc]
    ^-  hexb:bc
    0^0x0
  --
::
++  bip69
  |%
  ++  output-lte
    |=  [a=output:tx:bc b=output:tx:bc]
    ?.  =(value.a value.b)
      (lth value.a value.b)
    (lte dat.script-pubkey.a dat.script-pubkey.b)
  ::
  ++  input-lte
    |=  [a=input:tx:bc b=input:tx:bc]
    ?.  =(dat.txid.a dat.txid.b)
      (lth dat.txid.a dat.txid.b)
    (lte pos.a pos.b)
  ::
  ++  sort-outputs
    |=  os=(list output:tx:bc)
    (sort os output-lte)
  ::
  ++  sort-inputs
    |=  is=(list input:tx:bc)
    (sort is input-lte)
  --
--
