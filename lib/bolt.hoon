::  bolt.hoon
::  Library functions to implement Lightning BOLT RFCs.
::
/-  *bolt
/+  bc=bitcoin, script=bolt-script
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
  ++  p2wsh
    |=  s=script:script
    ^-  hexb:bc
    %-  en:script
    :~  %op-0
        :-  %op-pushdata
        %-  sha256:bc  (en:script s)
    ==
  ::
  ++  p2wpkh
    |=  p=pubkey
    ^-  hexb:bc
    %-  en:script
    :~  %op-0
        [%op-pushdata (hash-160:bc p)]
    ==
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
      %+  drop:byt:bc  26
      %-  sha256:bc
      %-  cat:byt:bc
      :~  [33 (compress-point oc)]
          [33 (compress-point ac)]
      ==
    --
  ::
  ++  funding
    |%
    ::
    ++  tx
      |=  $:  lpk=pubkey              ::  local pubkey
              rpk=pubkey              ::  remote pubkey
              amt=sats:bc             ::  funding amount
              ins=(list input:tx:bc)  ::  funding inputs
              chg=output:tx:bc        ::  change output
              ws=(list witness)       ::  input witnesses
          ==
      ^-  data:^tx
      :-  :*  is=ins
              os=(sort-outputs:bip69 ~[(output lpk rpk amt) chg])
              locktime=0
              nversion=2
              segwit=(some 1)
          ==
          ws=ws
    ::
    ++  output
      |=  [p1=pubkey p2=pubkey amt=sats:bc]
      ^-  output:tx:bc
      :*  script-pubkey=(p2wsh (output-script p1 p2))
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
    --
  ::
  ++  commitment
    |%
    ::  +tx:commitment:bolt-tx:
    ::
    ::    Commitment Transaction Construction
    ::
    ::    This section ties the previous sections together to
    ::    detail the algorithm for constructing the commitment
    ::    transaction for one peer: given that peer's
    ::    dust_limit_satoshis, the current feerate_per_kw, the
    ::    amounts due to each peer (to_local and to_remote),
    ::    and all committed HTLCs:
    ::
    ::    Initialize the commitment transaction input and
    ::    locktime, as specified in Commitment Transaction.
    ::
    ::    Calculate which committed HTLCs need to be trimmed
    ::      (see Trimmed Outputs).
    ::
    ::    Calculate the base commitment transaction fee.
    ::
    ::    Subtract this base fee from the funder (either
    ::      to_local or to_remote). If option_anchor_outputs
    ::      applies to the commitment transaction, also
    ::      subtract two times the fixed anchor size of 330 sats
    ::      from the funder (either to_local or to_remote).
    ::
    ::    For every offered HTLC, if it is not trimmed, add an
    ::      offered HTLC output.
    ::
    ::    For every received HTLC, if it is not trimmed, add
    ::      an received HTLC output.
    ::
    ::    If the to_local amount is greater or equal to
    ::      dust_limit_satoshis, add a to_local output.
    ::
    ::    If the to_remote amount is greater or equal to
    ::      dust_limit_satoshis, add a to_remote output.
    ::
    ::    If option_anchor_outputs applies to the commitment
    ::      transaction:
    ::
    ::      if to_local exists or there are untrimmed HTLCs,
    ::        add a to_local_anchor output
    ::
    ::      if to_remote exists or there are untrimmed HTLCs,
    ::        add a to_remote_anchor output
    ::
    ::    Sort the outputs into BIP 69+CLTV order.
    ::
    ++  tx
      |=  $:  c=chan
              to-local=msats
              to-remote=msats
              keyring=commitment-keyring
              our=?
          ==
      |^  ^-  data:^tx
      =|  txd=data:^tx
      %_  txd
          nversion  2
          locktime  (locktime ocn)
          segwit    (some 1)
          is        ~[(input funding-outpoint.c ocn)]
          os        (outputs c keyring to-local-sats to-remote-sats our)
          ws        (witnesses our.c her.c)
      ==
      ::
      ++  ocn  (obscured-commitment-number c)
      ::
      ++  to-local-sats
        =/  fee=sats:bc  (tx-fee c)
        =/  =sats:bc     (msats-to-sats to-local)
        ?:  initiator.c
          ?:  (lth sats fee)
            0
          (sub sats fee)
        sats
      ::
      ++  to-remote-sats
        =/  fee=sats:bc  (tx-fee c)
        =/  =sats:bc     (msats-to-sats to-remote)
        ?:  initiator.c
          sats
        ?:  (lth sats fee)
          0
        (sub sats fee)
      --
    ::
    ++  outputs
      |=  $:  c=chan
              keyring=commitment-keyring
              to-local-sats=sats:bc
              to-remote-sats=sats:bc
              our=?
          ==
      |^  ^-  (list output:tx:bc)
      %-  sort-outputs:bip69
      %-  zing
      :~
        ?.  (lth to-local-sats dust-limit.c)
          ~[local-out]
        ~
        ::
        ?.  (lth to-remote-sats dust-limit.c)
          ~[remote-out]
        ~
        ::
        %+  htlc-outputs  %.n
        offered.commit-state.our.c
        ::
        %+  htlc-outputs  %.y
        received.commit-state.our.c
      ==
      ++  local-out
        ^-  output:tx:bc
        %:  local-output
          revocation-key.keyring
          to-local-key.keyring
          to-self-delay.c
          to-local-sats
        ==
      ::
      ++  remote-out
        ^-  output:tx:bc
        %+  remote-output
          to-remote-key.keyring
        to-remote-sats
      ::
      ++  htlc-outputs
        |=  [received=? htlcs=(list ^htlc)]
        %+  turn
          (skip htlcs (htlc-trimmed received))
        (htlc-output received)
      ::
      ++  htlc-output
        |=  r=?
        |=  h=^htlc
        (output:htlc c h keyring r our)
      ::
      ++  htlc-trimmed
        |=  r=?
        |=  h=^htlc
        (is-trimmed:htlc c h r)
      --
    ::
    ++  witnesses
      |=  [our=chlen her=chlen]
      |^  ^-  (list witness)
      :~  %-  zing
          :~  ~[0^0x0]
              signatures
              ~[(en:script witness-script)]
          ==
      ==
      ++  witness-script
        %+  output-script:funding
          funding-pubkey.our
        funding-pubkey.her
      ::
      ++  signatures
        %-  sort-signatures
        :~  [funding-signature.our funding-pubkey.our]
            [funding-signature.her funding-pubkey.her]
        ==
      --
    ::
    ++  obscured-commitment-number
      |=  c=chan
      |^  ^-  @ud
      %^    obscure-commitment-number
          commitment-number.commit-state.our.c
        payment.basepoints:open-state
      payment.basepoints:accept-state
      ::
      ++  open-state    ?:(initiator.c our.c her.c)
      ++  accept-state  ?:(initiator.c her.c our.c)
      --
    ::
    ++  tx-fee
      |=  c=chan
      |^  ^-  sats:bc
      (base-fee feerate-per-kw.c anchor-outputs.c num-htlcs)
      ::
      ++  num-htlcs
        ^-  @ud
        %+  add
        %-  lent
          %+  skip  offered.commit-state.our.c
          |=  h=^htlc
          (is-trimmed:htlc c h %.n)
        %-  lent
          %+  skip  received.commit-state.our.c
          |=  h=^htlc
          (is-trimmed:htlc c h %.y)
      --
    ::
    ++  expected-weight
      |=  [anchor=? num-htlcs=@ud]
      ^-  @ud
      ?.  anchor
        (add 724 (mul 172 num-htlcs))
      (add 1.124 (mul 172 num-htlcs))
    ::
    ++  base-fee
      |=  [feerate-per-kw=@ud anchor=? num-htlcs=@ud]
      ^-  sats:bc
      %+  fee-by-weight
        feerate-per-kw
      (expected-weight anchor num-htlcs)
    ::  +locktime:commitment:bolt-tx:
    ::
    ::    Upper 8 bits are 0x20, lower 24 bits are the lower
    ::    24 bits of the obscured commitment number.
    ::
    ++  locktime
      |=  ocn=@ud
      %+  con  (lsh [3 3] 0x20)
      (dis 0xff.ffff ocn)
    ::  +sequence:commitment:bolt-tx:
    ::
    ::    Upper 8 bits are 0x80, lower 24 bits are upper
    ::    24 bits of the obscured commitment number.
    ::
    ++  sequence
      |=  ocn=@ud
      ^-  hexb:bc
      :-  4
      %+  con  (lsh [3 3] 0x80)
      %+  rsh  [3 3]
      (dis 0xffff.ff00.0000 ocn)
    ::
    ++  anchor-size  ^-(sats:bc 330)
    ::  +input:commitment:bolt-tx: generate input from funding-outpoint
    ::
    ++  input
      |=  [o=outpoint ocn=@ud]
      ^-  input:tx:bc
      :*  txid=txid.o
          pos=pos.o
          sequence=(sequence ocn)
          script-sig=~
          pubkey=~
          value=sats.o
      ==
    ::
    ++  local-output
      |=  $:  =revocation=pubkey
              =local-delayed=pubkey
              to-self-delay=@ud
              to-local=sats:bc
          ==
      |^  ^-  output:tx:bc
      :*  script-pubkey=(p2wsh script)
          value=to-local
      ==
      ++  script
        %:  local-output-script
          revocation-pubkey=revocation-pubkey
          local-delayed-pubkey=local-delayed-pubkey
          to-self-delay=to-self-delay
        ==
      --
    ::
    ++  remote-output
      |=  [=remote=pubkey to-remote=sats:bc]
      ^-  output:tx:bc
      :*  script-pubkey=(p2wpkh remote-pubkey)
          value=to-remote
      ==
    ::
    ++  anchor-output
      |=  [=pubkey amt=sats:bc]
      ^-  output:tx:bc
      :*  script-pubkey=(p2wsh (anchor-output-script pubkey))
          value=amt
      ==
    ::
    ++  local-output-script
      |=  $:  =revocation=pubkey
              =local-delayed=pubkey
              to-self-delay=@ud
          ==
     |^  ^-  script:script
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
        %-  flip:byt:bc
        :*  wid=2
            dat=to-self-delay
        ==
      --
    ::
    ++  remote-output-script
      |=  =pubkey
      :~  [%op-pushdata pubkey]
          %op-checksigverify
          %op-1
          %op-checksequenceverify
      ==
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
    --
  ::
  ++  htlc
    |%
    ++  output
      |=  $:  c=chan
              h=^htlc
              k=commitment-keyring
              received=?  ::  received HTLC
              our=?       ::  our commitment
          ==
      ?:  ?&(received our)
        (received-output:htlc c k h)
      ?:  received
        (offered-output:htlc c k h)
      ?:  our
        (offered-output:htlc c k h)
      (received-output:htlc c k h)
    ::
    ++  is-trimmed
      |=  [c=chan h=^htlc received=?]
      |^  ^-  ?
      ?|  %+  lth  amount-sats  fee
          %+  lth
            %+  sub  amount-sats  fee
          dust-limit.c
      ==
      ++  amount-sats  (msats-to-sats amount-msat.h)
      ::
      ++  fee
        ?:  received
          %-  success-fee  c
        %-  timeout-fee  c
      --
    ::
    ++  success-fee
      |=  c=chan
      %+  fee-by-weight
        feerate-per-kw.c
      ?.(anchor-outputs.c 703 706)
    ::
    ++  timeout-fee
      |=  c=chan
      %+  fee-by-weight
        feerate-per-kw.c
      ?.(anchor-outputs.c 663 666)
    ::
    ++  offered-output
      |=  [c=chan k=commitment-keyring h=^htlc]
      |^  ^-  output:tx:bc
      :*  script-pubkey=(p2wsh script)
          value=(msats-to-sats amount-msat.h)
      ==
      ++  script  (offered-script k payment-hash.h anchor-outputs.c)
      --
    ::
    ++  received-output
      |=  [c=chan k=commitment-keyring h=^htlc]
      |^  ^-  output:tx:bc
      :*  script-pubkey=(p2wsh script)
          value=(msats-to-sats amount-msat.h)
      ==
      ++  script  (received-script k payment-hash.h cltv-expiry.h anchor-outputs.c)
      --
    ::
    ++  offered-script
      |=  $:  keys=commitment-keyring
              payment-hash=hexb:bc
              confirmed-spend=?
          ==
      ^-  script:script
      %+  welp
        :~  %op-dup
            %op-hash160
            [%op-pushdata (hash-160:bc revocation-key.keys)]
            %op-equal
            %op-if
            %op-checksig
            %op-else
            [%op-pushdata remote-htlc-key.keys]
            %op-swap
            %op-size
            [%op-pushdata [1 32]]
            %op-equal
            %op-notif
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
    ::
    ++  received-script
      |=  $:  keys=commitment-keyring
              payment-hash=hexb:bc
              cltv-expiry=@ud
              confirmed-spend=?
          ==
      |^  ^-  script:script
      ;:  welp
        :~  %op-dup
            %op-hash160
            [%op-pushdata (hash-160:bc revocation-key.keys)]
            %op-equal
            %op-if
            %op-checksig
            %op-else
            [%op-pushdata remote-htlc-key.keys]
            %op-swap
            %op-size
            [%op-pushdata [1 32]]
            %op-equal
            %op-if
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
      ++  cltv-byts
        %-  flip:byt:bc
        :*  wid=2
            dat=cltv-expiry
        ==
      --
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
      |=  b=hexb:bc
        ?:  =(0 wid.b)
          ~[1^0x0]
        ~[(en:csiz:bc wid.b) b]
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
::
++  keys
  =,  secp256k1:secp:crypto
  |%
  ++  point-hash
    |=  [a=point b=point]
    ^-  hexb:bc
    %-  sha256:bc
    %-  cat:byt:bc
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
    |=  [per-commitment-point=point base=point]
    ^-  pubkey
    :-  33
    %-  compress-point
    %^    add-mul-hash
        per-commitment-point
      base
    base
  ::
  ++  derive-privkey
    |=  [per-commitment-point=point base=point secret=hexb:bc]
    ^-  privkey
    :-  32
    %+  mod
      %+  add
        dat:(point-hash per-commitment-point base)
      dat.secret
    n:t
  ::
  ++  derive-revocation-pubkey
    |=  [per-commitment-point=point base=point]
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
    |=  $:  per-commitment-point=point
            revocation-basepoint=point
            revocation-basepoint-secret=hexb:bc
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
        per-commitment-point
      htlc.basepoints.local
    ::
    ++  remote-htlc-pubkey
      %+  derive-pubkey
        per-commitment-point
      htlc.basepoints.remote
    ::
    ++  to-local-pubkey
      %+  derive-pubkey
        per-commitment-point
      ?:  our
        delayed-payment.basepoints.local
      delayed-payment.basepoints.remote
    ::
    ++  to-remote-pubkey
      %+  derive-pubkey
        per-commitment-point
      ?:  our
        payment.basepoints.remote
      payment.basepoints.local
    ::
    ++  revocation-pubkey
      %+  derive-revocation-pubkey
        per-commitment-point
      ?:  our
        revocation.basepoints.remote
      revocation.basepoints.local
    --
  ::
  ++  generate-per-commitment-secret
    |=  [seed=hexb:bc i=@ud]
    |^  ^-  hexb:bc
    =/  p=hexb:bc  seed
    =/  b=@ud      47
    |-
    ?:  =(0 b)
      p
    ?:  (test-bit b p)
      %_  $
        b  (dec b)
        p  (sha256:bc (flip-bit b p))
      ==
    $(b (dec b), p p)
    ::
    ++  test-bit
      |=  [n=@ p=hexb:bc]
      =(1 (get-bit n p))
    ::
    ++  get-bit
      |=  [n=@ p=hexb:bc]
      ~|  "Unimplemented"
      !!
    ::
    ++  flip-bit
      |=  [n=@ b=hexb:bc]
      ~|  "Unimplemented"
      !!
    --
  --
--
