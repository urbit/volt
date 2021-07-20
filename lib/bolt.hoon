::  bolt.hoon
::  Library functions to implement Lightning BOLT RFCs.
::
/-  *bolt
/+  bc=bitcoin, bcu=bitcoin-utils, btc-script=bolt-script
|%
::  +bolt-tx
::    helpers for building & signing commitment/HTLC txs
::
++  bolt-tx
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
  ::
  ++  fee-by-weight
    |=  [feerate-per-kw=@ud weight=@ud]
    ^-  @ud
    (div (mul weight feerate-per-kw) 1.000)
  ::  +sort-signatures:bolt-tx: order a pair of signature, pubkey pairs
  ::
  ::    The funding transaction witness script orders pubkeys
  ::    lexicographically, so a spend from a funding output needs to
  ::    arrange the signatures in the same order.
  ::
  ++  sort-signatures
    |=  sigs=(list (pair signature pubkey))
    |^  ^-  (list signature)
    (turn (sort sigs pk-lte) head)
    ::
    ++  pk-lte
      |=  [a=[s=signature p=pubkey] b=[s=signature p=pubkey]]
      (lte dat.p.a dat.p.b)
    --
  ::
  ++  obscure-commitment-number
    =,  secp256k1:secp:crypto
    |=  [cn=commitment-number oc=point ac=point]
    |^  ^-  @ud
    (mix dat:mask cn)
    ::
    ++  mask
      ^-  hexb:bc
      %+  drop:byt:bcu  26
      %-  sha256:bcu
      %-  cat:byt:bcu
      :~  [33 (compress-point oc)]
          [33 (compress-point ac)]
      ==
    --
  ::
  ++  anchor-size  330
  ::
  ++  funding-tx
    |=  $:  lpk=pubkey              ::  local pubkey
            rpk=pubkey              ::  remote pubkey
            amt=sats:bc             ::  funding amount
            ins=(list input:tx:bc)  ::  funding inputs
            chg=output:tx:bc        ::  change output
            ws=(list witness)       ::  input witnesses
        ==
    |^  ^-  data:tx
    :-  :*  is=ins
            os=outputs
            locktime=0
            nversion=2
            segwit=(some 1)
        ==
    ws=ws
    ::
    ++  script-pubkey
      %-  p2wsh:script
      %+  funding-output:script
        lpk
      rpk
    ::
    ++  outputs
      ^-  (list output:tx:bc)
      %-  sort-outputs:bip69
      :~
        :*  script-pubkey=script-pubkey
            value=amt
        ==
        chg
      ==
    --
  ::  +commitment:bolt-tx: generate the tx data for the commitment state
  ::
  ::    See: https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#commitment-transaction-construction
  ::
  ++  commitment
    |_  $:  c=chan
            keyring=commitment-keyring
            to-local=msats
            to-remote=msats
            our=?
        ==
    ::
    ++  obscured-commitment-number
      |^
      ^-  @ud
      %^    obscure-commitment-number
          commitment-number.commit-state.our.c
        payment.basepoints:open-state
      payment.basepoints:accept-state
      ::
      ++  open-state
        ?:(initiator.c our.c her.c)
      ::
      ++  accept-state
        ?:(initiator.c her.c our.c)
      --
    ::
    ++  htlc-success-fee
      %+  fee-by-weight
        feerate-per-kw.c
      ?.(anchor-outputs.c 703 706)
    ::
    ++  htlc-timeout-fee
      %+  fee-by-weight
        feerate-per-kw.c
      ?.(anchor-outputs.c 663 666)
    ::
    ++  is-trimmed
      |=  [h=htlc received=?]
      |^  ^-  ?
      ?|  (lth amount-sats fee)
          %+  lth
          %+  sub  amount-sats  fee
          dust-limit.c
      ==
      ::
      ++  amount-sats
        %-  msats-to-sats
        amount-msat.h
      ::
      ++  fee
        ?:  received
          htlc-success-fee
        htlc-timeout-fee
      --
    ::
    ++  offered-htlcs
      %+  skip  offered.commit-state.our.c
      |=  h=htlc
      (is-trimmed h %.n)
    ::
    ++  received-htlcs
      %+  skip  received.commit-state.our.c
      |=  h=htlc
      (is-trimmed h %.y)
    ::
    ++  num-untrimmed-htlcs
      ^-  @ud
      %+  add
      %-  lent  offered-htlcs
      %-  lent  received-htlcs
    ::
    ++  expected-weight
      ^-  @ud
      ?.  anchor-outputs.c
        (add 724 (mul 172 num-untrimmed-htlcs))
      (add 1.124 (mul 172 num-untrimmed-htlcs))
    ::
    ++  base-fee
      ^-  sats:bc
      %+  fee-by-weight
        feerate-per-kw.c
      expected-weight
    ::
    ++  subtract-fee-and-anchor
      |=  amt=sats:bc
      |^  ^-  @ud
      %+  subz
      %+  subz  amt  base-fee
      ?:  anchor-outputs.c
        %+  mul  2
        anchor-size
      0
      ++  subz
        |=  [a=@ b=@]
        ?:  (lth a b)
          0
        (sub a b)
      --
    ::
    ++  to-local-sats
      ?:  initiator.c
        %-  subtract-fee-and-anchor
        %-  msats-to-sats  to-local
      (msats-to-sats to-local)
    ::
    ++  to-remote-sats
      ?.  initiator.c
        %-  subtract-fee-and-anchor
        %-  msats-to-sats  to-remote
      (msats-to-sats to-remote)
    ::
    ++  local-output
      |^
      ^-  (unit output:tx:bc)
      ?:  (lth to-local-sats dust-limit.c)
        ~
      %-  some
      :*  script-pubkey=script-pubkey
          value=to-local-sats
      ==
      ++  script-pubkey
        %-  p2wsh:script
        %^    local-output:script
            revocation-key.keyring
          to-local-key.keyring
        to-self-delay.c
      --
    ::
    ++  remote-output
      |^
      ^-  (unit output:tx:bc)
      ?:  (lth to-remote-sats dust-limit.c)
        ~
      %-  some
      :*  script-pubkey=script-pubkey
          value=to-remote-sats
      ==
      ++  script-pubkey
        ?:  anchor-outputs.c
          %-  p2wsh:script
          %-  remote-output:script
          to-remote-key.keyring
        %-  p2wpkh:script
        to-remote-key.keyring
      --
    ::
    ++  htlc-output
      |=  [h=htlc received=?]
      |^  ^-  output:tx:bc
      :*  script-pubkey=script-pubkey
          value=(msats-to-sats amount-msat.h)
      ==
      ++  script-pubkey
        %-  p2wsh:script
        ?:  ?&  received
                our
            ==
          received-script
        ?:  received
          offered-script
        ?:  our
          offered-script
        received-script
      ::
      ++  offered-script
        %^    htlc-offered:script
            keyring
          payment-hash.h
        anchor-outputs.c
      ::
      ++  received-script
        %:  htlc-received:script
          keys=keyring
          payment-hash=payment-hash.h
          cltv-expiry=cltv-expiry.h
          confirmed-spend=anchor-outputs.c
        ==
      --
    ::
    ++  anchor-output
      |=  =pubkey
      |^  ^-  output:tx:bc
      :*  script-pubkey=script-pubkey
          value=anchor-size
      ==
      ++  script-pubkey
        %-  p2wsh:script
        %-  anchor-output:script
        pubkey
      --
    ::
    ++  locktime
      ^-  @ud
      %+  con  (lsh [3 3] 0x20)
      (dis 0xff.ffff obscured-commitment-number)
    ::
    ++  sequence
      ^-  hexb:bc
      :-  4
      %+  con  (lsh [3 3] 0x80)
      %+  rsh  [3 3]
      (dis 0xffff.ff00.0000 obscured-commitment-number)
    ::
    ++  inputs
      ^-  (list input:tx:bc)
      :~
        :*  txid=txid.funding-outpoint.c
            pos=pos.funding-outpoint.c
            sequence=sequence
            script-sig=~
            pubkey=~
            value=sats.funding-outpoint.c
        ==
      ==
    ::
    ++  outputs
      ^-  (list output:tx:bc)
      %-  sort-outputs:bip69
      %-  zing
      :~
        ?:  =(~ local-output)
          ~
        ~[(need local-output)]
        ::
        ?:  =(~ remote-output)
          ~
        ~[(need remote-output)]
        ::
        %+  turn  offered-htlcs
        |=  h=htlc
        (htlc-output h %.n)
        ::
        %+  turn  received-htlcs
        |=  h=htlc
        (htlc-output h %.y)
        ::
        ?:  ?&  !=(~ local-output)
                anchor-outputs.c
            ==
          ~[(anchor-output funding-pubkey.our.c)]
        ~
        ::
        ?:  ?&  !=(~ remote-output)
                anchor-outputs.c
            ==
          ~[(anchor-output funding-pubkey.her.c)]
        ~
      ==
    ::
    ++  witnesses
      |^
      ^-  (list witness)
      :_  ~
      %-  zing
      :~  ~[0^0x0]
          signatures
          ~[(en:btc-script witness-script)]
      ==
      ::
      ++  witness-script
        %+  funding-output:script
          funding-pubkey.our.c
        funding-pubkey.her.c
      ::
      ++  signatures
        %-  sort-signatures
        :~  :-  funding-signature.our.c
            funding-pubkey.our.c
            ::
            :-  funding-signature.her.c
            funding-pubkey.her.c
        ==
      --
    ::
    ++  tx-data
      ^-  data:tx
      :-
      :*  is=inputs
          os=outputs
          locktime=locktime
          nversion=2
          segwit=(some 1)
      ==
      ws=witnesses
    --
  ::
  ++  htlc-spend
    |=  $:  c=chan
            h=htlc
            keyring=commitment-keyring
            =commitment=outpoint
            timeout=?
        ==
    |^  ^-  data:tx
    :-
    :*  is=~[input]
        os=~[output]
        locktime=?:(timeout cltv-expiry.h 0)
        nversion=2
        segwit=(some 1)
    ==
    ws=~[witness]
    ::
    ++  input
      :*  txid=txid.commitment-outpoint
          pos=pos.commitment-outpoint
          sequence=sequence
          script=sig=~
          pubkey=~
          value=(msats-to-sats amount-msat.h)
      ==
    ::
    ++  output
      :*  script-pubkey=(p2wsh:script script-pubkey)
          value=(sub (msats-to-sats amount-msat.h) fee)
      ==
    ::
    ++  sequence
      ^-  hexb:bc
      :-  4
      ?:  anchor-outputs.c
        0x1
      0x0
    ::
    ++  witness
      ;:  weld
        :~  0^0x0
            (need remote-sig.h)
            (need local-sig.h)
        ==
        ?:  timeout  ~
        ~[(need payment-preimage.h)]
      ==
    ::
    ++  script-pubkey
      %^    htlc-spend:script
          revocation-key.keyring
        to-local-key.keyring
      to-self-delay.c
    ::
    ++  fee
      %+  fee-by-weight
        feerate-per-kw.c
      weight
    ::
    ++  weight
      ?:  ?&(anchor-outputs.c timeout)
        666
      ?:  timeout
        663
      ?:  anchor-outputs.c
        706
      703
    --
  ::
  ++  htlc-timeout
    |=  [c=chan h=htlc keyring=commitment-keyring =commitment=outpoint]
    ^-  data:tx
    %:  htlc-spend
        c=c
        h=h
        keyring=keyring
        commitment-outpoint=commitment-outpoint
        timeout=%.y
    ==
  ::
  ++  htlc-success
    |=  [c=chan h=htlc keyring=commitment-keyring =commitment=outpoint]
    ^-  data:tx
    %:  htlc-spend
        c=c
        h=h
        keyring=keyring
        commitment-outpoint=commitment-outpoint
        timeout=%.n
    ==
  ::  +script:bolt-tx:  script generators
  ::
  ++  script
    |%
    ::
    ++  p2wsh
      |=  s=script:btc-script
      ^-  hexb:bc
      %-  en:btc-script
      :~  %op-0
          :-  %op-pushdata
          %-  sha256:bcu  (en:btc-script s)
      ==
    ::
    ++  p2wpkh
      |=  p=pubkey
      ^-  hexb:bc
      %-  en:btc-script
      :~  %op-0
          [%op-pushdata (hash-160:bcu p)]
      ==
    ::
    ++  funding-output
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
    ++  local-output
      |=  $:  =revocation=pubkey
              =local-delayed=pubkey
              to-self-delay=@ud
          ==
     |^  ^-  script:btc-script
     :~  %op-if
         [%op-pushdata revocation-pubkey]
         %op-else
         [%op-pushdata to-self-delay-byts]
         %op-checksequenceverify
         %op-drop
         [%op-pushdata local-delayed-pubkey]
         %op-endif
         %op-checksig
      ==
      ++  to-self-delay-byts
        %-  flip:byt:bcu
        :*  wid=2
            dat=to-self-delay
        ==
      --
    ::
    ++  remote-output
      |=  =pubkey
      ^-  script:btc-script
      :~  [%op-pushdata pubkey]
          %op-checksigverify
          %op-1
          %op-checksequenceverify
      ==
    ::
    ++  anchor-output
      |=  =pubkey
      ^-  script:btc-script
      :~  [%op-pushdata pubkey]
          %op-checksig
          %op-ifdup
          %op-notif
          %op-16
          %op-checksequenceverify
          %op-endif
      ==
    ::
    ++  htlc-prefix
      |=  keys=commitment-keyring
      ^-  script:btc-script
      :~  %op-dup
          %op-hash160
          [%op-pushdata (hash-160:bcu revocation-key.keys)]
          %op-equal
          %op-if
          %op-checksig
          %op-else
          [%op-pushdata remote-htlc-key.keys]
          %op-swap
          %op-size
          [%op-pushdata [1 32]]
          %op-equal
      ==
    ::
    ++  htlc-offered
      |=  $:  keys=commitment-keyring
              payment-hash=hexb:bc
              confirmed-spend=?
          ==
      ^-  script:btc-script
      ;:  welp
        %-  htlc-prefix  keys
        :~  %op-notif
            %op-drop
            %op-2
            %op-swap
            [%op-pushdata local-htlc-key.keys]
            %op-2
            %op-checkmultisig
            %op-else
            %op-hash160
            [%op-pushdata [20 (ripemd-160:ripemd:crypto payment-hash)]]
            %op-equalverify
            %op-checksig
            %op-endif
        ==
        ?:  confirmed-spend
          :~  %op-1
              %op-checksequenceverify
              %op-drop
              %op-endif
          ==
        ~[%op-endif]
      ==
    ::
    ++  htlc-received
      |=  $:  keys=commitment-keyring
              payment-hash=hexb:bc
              cltv-expiry=@ud
              confirmed-spend=?
          ==
      |^  ^-  script:btc-script
      ;:  welp
        %-  htlc-prefix  keys
        :~  %op-if
            %op-hash160
            [%op-pushdata [20 (ripemd-160:ripemd:crypto payment-hash)]]
            %op-equalverify
            %op-2
            %op-swap
            [%op-pushdata local-htlc-key.keys]
            %op-2
            %op-checkmultisig
            %op-else
            %op-drop
            [%op-pushdata cltv-byts]
            %op-checklocktimeverify
            %op-drop
            %op-checksig
            %op-endif
        ==
        ?.  confirmed-spend  ~
        :~  %op-1
            %op-checksequenceverify
            %op-drop
        ==
        ~[%op-endif]
      ==
      ::
      ++  cltv-byts
        %-  flip:byt:bcu
        :*  wid=2
            dat=cltv-expiry
        ==
      --
    ::
    ++  htlc-spend
      |=  $:  revocation-pubkey=pubkey
              local-delayed-pubkey=pubkey
              to-self-delay=@ud
          ==
      |^  ^-  script:btc-script
      :~  %op-if
          [%op-pushdata revocation-pubkey]
          %op-else
          [%op-pushdata to-self-delay-byts]
          %op-checksequenceverify
          %op-drop
          [%op-pushdata local-delayed-pubkey]
          %op-endif
          %op-checksig
      ==
      ++  to-self-delay-byts
        %-  flip:byt:bcu
        :*  wid=2
            dat=to-self-delay
        ==
      --
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
      %-  cat:byt:bcu
      :-  (en:csiz:bcu (lent w))
      %-  zing
      %+  turn  w
      |=  b=hexb:bc
        ?:  =(0 wid.b)
          ~[1^0x0]
        ~[(en:csiz:bcu wid.b) b]
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
      =^  n  b  (dea:csiz:bcu b)
      =|  acc=^witness
      |-
      ?:  =(0 n)  [(flop acc) b]
      =^  siz  b  (dea:csiz:bcu b)
      =^  elt  b
        [(take:byt:bcu siz b) (drop:byt:bcu siz b)]
      $(acc [elt acc], n (dec n), b b)
    --
  ::
  ++  segwit-encode
    |=  =data:tx
    ^-  hexb:bc
    %-  cat:byt:bcu:bc
    %-  zing
    :~  ~[(flip:byt:bcu:bc 4^nversion.data)]
        ?:  ?&  ?=(^ segwit.data)
                ?=(^ ws.data)
            ==
          :~  [wid=2 dat=0x1]
          ==
        ~
        ~[(en:csiz:bcu (lent is.data))]
        (turn is.data input:en:txu:bc)
        ~[(en:csiz:bcu (lent os.data))]
        (turn os.data output:en:txu:bc)
        (turn ws.data witness:en)
        ~[(flip:byt:bcu 4^locktime.data)]
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
      dat:(take:byt:bcu 4 (flip:byt:bcu b))
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
::
++  keys
  =,  secp256k1:secp:crypto
  |%
  ++  point-hash
    |=  [a=point b=point]
    ^-  hexb:bc
    %-  sha256:bcu
    %-  cat:byt:bcu
    :~  [33 (compress-point a)]
        [33 (compress-point b)]
    ==
  ::
  ++  add-mul-hash
    |=  [a=point b=point c=point]
    %+  add-points
      %+  mul-point-scalar
        g:t
      dat:(point-hash a b)
    c
  ::
  ++  derive-pubkey
    |=  [base=point per-commitment-point=point]
    ^-  pubkey
    :-  33
    %-  compress-point
    %^    add-mul-hash
        per-commitment-point
      base
    base
  ::
  ++  derive-privkey
    |=  [base=point per-commitment-point=point secret=hexb:bc]
    ^-  privkey
    :-  32
    %+  mod
      %+  add
        dat:(point-hash per-commitment-point base)
      dat.secret
    n:t
  ::
  ++  derive-revocation-pubkey
    |=  [base=point per-commitment-point=point]
    |^  ^-  pubkey
    :-  33
    %-  compress-point
    %+  add-points
      (mul-point-scalar base dat:r)
    (mul-point-scalar per-commitment-point dat:c)
    ::
    ++  r  (point-hash base per-commitment-point)
    ++  c  (point-hash per-commitment-point base)
    --
  ::
  ++  derive-revocation-privkey
    |=  $:  revocation-basepoint=point
            revocation-basepoint-secret=hexb:bc
            per-commitment-point=point
            per-commitment-secret=hexb:bc
        ==
    |^  ^-  privkey
    :-  32
    %+  mod
      %+  add
        (mul dat.revocation-basepoint-secret dat:r)
      (mul dat.per-commitment-secret dat:c)
    n:t
    ++  r  (point-hash revocation-basepoint per-commitment-point)
    ++  c  (point-hash per-commitment-point revocation-basepoint)
    --
  ::
  ++  derive-commitment-keys
    |=  $:  per-commitment-point=point
            local=chlen
            remote=chlen
            our=?
        ==
    |^  ^-  commitment-keyring
    :*  local-htlc-key=local-htlc-pubkey
        remote-htlc-key=remote-htlc-pubkey
        to-local-key=to-local-pubkey
        to-remote-key=to-remote-pubkey
        revocation-key=revocation-pubkey
    ==
    ::
    ++  local-htlc-pubkey
      %+  derive-pubkey
        htlc.basepoints.local
      per-commitment-point
    ::
    ++  remote-htlc-pubkey
      %+  derive-pubkey
        htlc.basepoints.remote
      per-commitment-point
    ::
    ++  to-local-pubkey
      %+  derive-pubkey
        ?:  our
          delayed-payment.basepoints.local
        delayed-payment.basepoints.remote
      per-commitment-point
    ::
    ++  to-remote-pubkey
      %+  derive-pubkey
        ?:  our
          payment.basepoints.remote
        payment.basepoints.local
      per-commitment-point
    ::
    ++  revocation-pubkey
      %+  derive-revocation-pubkey
        ?:  our
          revocation.basepoints.remote
        revocation.basepoints.local
      per-commitment-point
    --
  --
::
++  commitment-secret
  |%
  +$  index  @u
  +$  seed   hexb:bc
  +$  commit-secret  hexb:bc
  ::
  ++  compute-commitment-point
    =,  secp256k1:secp:crypto
    |=  =commit-secret
    ^-  point
    %+  mul-point-scalar
      g:t
    dat:commit-secret
  ::
  ++  first-index
    ^-  @ud
    281.474.976.710.655
  ::
  ++  generate-from-seed
    |=  [=seed i=index]
    |^  ^-  commit-secret
    =/  p=@    dat.seed
    =/  b=@ud  48
    |-
    =.  b  (dec b)
    =?  p  (test-bit b i)
      %+  shay  32
      %+  flip-bit  b  p
    ?:  =(0 b)
      :*
        wid=32
        dat=(swp 3 p)
      ==
    $(b b, p p)
    ::
    ++  test-bit
      |=  [n=@ p=@]
      =(1 (get-bit n p))
    ::
    ++  get-bit
      |=  [n=@ p=@]
      =/  byt=@  (div n 8)
      =/  bit=@  (mod n 8)
      %+  dis  0x1
      %+  rsh  [0 bit]
      %+  rsh  [3 byt]
      p
    ::
    ++  flip-bit
      |=  [n=@ b=@]
      =/  byt=@  (div n 8)
      =/  bit=@  (mod n 8)
      %+  mix  b
      %+  lsh  [0 bit]
      %+  lsh  [3 byt]
      1
    --
  ::
  ++  next
    |=  [=seed i=index]
    ^-  (pair commit-secret index)
    :-  (generate-from-seed seed i)
        (dec i)
  ::
  ++  init-from-seed
    |=  =seed
    ^-  (pair commit-secret index)
    %+  next
      seed
    first-index
  --
--
