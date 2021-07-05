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
      =:  nversion.txd  2
          locktime.txd  (locktime obscured-commitment-number)
          segwit.txd    (some 1)
      ==
      ::
      =.  is.txd
        ~[(input funding-outpoint.c obscured-commitment-number)]
      ::
      =.  os.txd
        =/  local-out=output:tx:bc
          %:  local-output
            revocation-key.keyring
            to-local-key.keyring
            to-self-delay.c
            to-local-sats
          ==
        =/  remote-out=output:tx:bc
          (remote-output to-remote-key.keyring to-remote-sats)
        (sort-outputs:bip69 ~[local-out remote-out])
      ::
      =.  ws.txd
        =/  pka=pubkey     funding-pubkey.our.c
        =/  pkb=pubkey     funding-pubkey.her.c
        =/  sga=signature  funding-signature.our.c
        =/  sgb=signature  funding-signature.her.c
        =/  sig=(list signature)
          %-  sort-signatures
          :~  [sga pka]
              [sgb pkb]
          ==
        =/  ws=script:script
          (output-script:funding pka pkb)
        :~
          %-  zing
          :~  ~[0^0x0]
              sig
              ~[(en:script ws)]
          ==
        ==
      ::
      txd
      ::
      ++  fee
        ^-  sats:bc
        (base-fee feerate-per-kw.c anchor-outputs.c num-htlcs)
      ::
      ++  num-htlcs
        ^-  @ud
        %+  add
        %-  lent  offered.commit-state.our.c
        %-  lent  received.commit-state.our.c
      ::
      ++  obscured-commitment-number
        ^-  @ud
        %^    obscure-commitment-number
            commitment-number.commit-state.our.c
          payment.basepoints:open-state
        payment.basepoints:accept-state
      ::
      ++  open-state    ?:(initiator.c our.c her.c)
      ::
      ++  accept-state  ?:(initiator.c her.c our.c)
      ::
      ++  to-local-sats
        ?:  initiator.c
          (sub (msats-to-sats to-local) fee)
        (msats-to-sats to-local)
      ::
      ++  to-remote-sats
        ?:  initiator.c
          (msats-to-sats to-remote)
        (sub (msats-to-sats to-remote) fee)
      --
    ::
    ++  expected-weight
      |=  [anchor=? num-htlcs=@ud]
      ^-  @ud
      ?.  anchor
        (add 724 (mul 172 num-htlcs))
      (add 1.124 (mul 172 num-htlcs))
    ::
    ++  fee-by-weight
      |=  [feerate-per-kw=@ud weight=@ud]
      ^-  @ud
      (div (mul weight feerate-per-kw) 1.000)
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
      |^  ^-  output:tx:bc
      :*  script-pubkey=(p2wsh script)
          value=amt
      ==
      ++  script  (anchor-output-script pubkey)
      --
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
    ++  is-trimmed
      |=  [c=chan h=^htlc]
      (lth (msats-to-sats amount-msat.h) dust-limit.c)
    ::
    ++  offered-script
      |=  [c=chan h=htlc-pend]
      |^
      ?:  anchor-outputs.c
        with-anchors
      without-anchors
      ::
      ++  with-anchors
        :~  %op-dup
            %op-hash160
            [%op-pushdata (hash-160:bc revocation-pubkey.h)]
            %op-equal
            %op-if
            %op-checksig
            %op-else
            [%op-pushdata !!]
            %op-swap
            %op-size
            [%op-pushdata [1 32]]
            %op-equal
            %op-notif
            %op-drop
            %op-2
            %op-swap
            [%op-pushdata !!]
            %op-2
            %op-checkmultisig
            %op-else
            %op-hash160
            [%op-pushdata (hash-160:bc payment-hash.htlc.h)]
            %op-equalverify
            %op-checksig
            %op-endif
            %op-1
            %op-checksequenceverify
            %op-drop
            %op-endif
        ==
      ::
      ++  without-anchors
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
      --
    ::
    ++  received-script
      |=  [c=chan h=htlc-pend]
      |^
      ?:  anchor-outputs.c
        with-anchors
      without-anchors
      ++  with-anchors  ~
      ::
      ++  without-anchors  ~
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
  ++  per-commitment-secret
    |=  [seed=hexb:bc i=@ud]
    |^  ^-  hexb:bc
    =/  p=hexb:bc  seed
    =/  b=@ud      47
    |-
    ?:  =(0 b)
      p
    ?:  =(1 (get-bit b p))
      %_  $
        b  (dec b)
        p  (sha256:bc (flip-bit b p))
      ==
    $(b (dec b), p p)
    ::
    ++  get-bit
      |=  [n=@ b=hexb:bc]
      ~|  "Unimplemented"
      !!
    ::
    ++  flip-bit
      |=  [n=@ b=hexb:bc]
      ~|  "Unimplemented"
      !!
    --
  ::
  ++  derive-commitment-keys
    |=  [per-commitment-point=point =basepoints our=?]
    |^  ^-  commitment-keyring
    ?:  our
      our-keys
    her-keys
    ::
    ++  our-keys
      :*  local-htlc-key=0^0x0
          remote-htlc-key=0^0x0
          to-local-key=0^0x0
          to-remote-key=0^0x0
          revocation-key=0^0x0
      ==
    ::
    ++  her-keys
      :*  local-htlc-key=0^0x0
          remote-htlc-key=0^0x0
          to-local-key=0^0x0
          to-remote-key=0^0x0
          revocation-key=0^0x0
      ==
    --
  --
--
