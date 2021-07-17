::
/-  *bolt
/+  *test, bolt, bc=bitcoin
|%
++  test-obscure-commitment-number
  =,  bolt-tx:bolt
  =,  secp:crypto
  =/  oc=point
    %-  decompress-point:secp256k1
    0x3.4f35.5bdc.b7cc.0af7.28ef.3cce.b961.5d90.684b.b5b2.ca5f.859a.b0f0.b704.0758.71aa
  =/  ac=point
    %-  decompress-point:secp256k1
    0x3.2c0b.7cf9.5324.a07d.0539.8b24.0174.dc0c.2be4.44d9.6b15.9aa6.c7f7.b1e6.6868.0991
  =/  cn=@ud  42
  %+  expect-eq
    !>(`@ux`(mix 0x2bb0.3852.1914 cn))
    !>(`@ux`(obscure-commitment-number cn oc ac))
::
++  sighash-test-vectors
  =,  bitcoin-txu:bolt
  ^-  (list (quip value:sighash @ux))
  :~  :-  ~[%all]                  0x1
      :-  ~[%none]                 0x2
      :-  ~[%single]               0x3
      :-  ~[%all %anyone-can-pay]  0x81
  ==
::
++  test-encode-sighash
  =,  bitcoin-txu:bolt
  %+  category  "sighash encoding"
  %-  zing
  %+  turn  sighash-test-vectors
    |=  q=(quip value:sighash @ux)
    %+  expect-eq
      !>((en:sighash (silt -.q)))
      !>(+.q)
::
++  test-decode-sighash
  =,  bitcoin-txu:bolt
  %+  category  "sighash decoding"
  %-  zing
  %+  turn  sighash-test-vectors
    |=  q=(quip value:sighash @ux)
    %+  expect-eq
      !>((silt -.q))
      !>((de:sighash +.q))
::
++  test-sort-inputs
  =,  bip69:bolt
  =|  a=input:tx:bc
  =|  b=input:tx:bc
  =|  c=input:tx:bc
  =.  txid.a
    :-  32
    0xe53.ec5d.fb2c.b8a7.1fec.32dc.9a63.4a35.b7e2.4799.295d.dd52.7821.7822.e0b3.1f57
  =.  pos.a  0
  =.  txid.b
    :-  32
    0x54ff.ff18.2965.ed09.57db.a123.9c27.164a.ce5a.73c9.b62a.660c.74b7.b7f1.5ff6.1e7a
  =.  pos.b  0
  =.  txid.c  txid.b
  =.  pos.c  1
  %+  expect-eq
    !>(~[a b c])
    !>((sort-inputs ~[b a c]))
::
++  test-segwit
  |^
  ;:  weld
    check-decode
    check-encode
  ==
  ::
  ++  check-decode
    %+  expect-eq
      !>  decoded-tx
      !>  %-  segwit-decode:bitcoin-txu:bolt
          raw-tx
  ::
  ++  check-encode
    %+  expect-eq
      !>  raw-tx
      !>  %-  segwit-encode:bitcoin-txu:bolt
          decoded-tx
  ::
  ++  decoded-inputs
    ^-  (list input:tx:bc)
    :~  :*  txid=input-txid
            pos=0
            sequence=[wid=4 dat=0x0]
            script-sig=~
            pubkey=~
            value=0
        ==
    ==
  ::
  ++  decoded-outputs
    ^-  (list output:tx:bc)
    :~  :*  script-pubkey=output1-script-pubkey
            value=25.000
        ==
        :*  script-pubkey=output2-script-pubkey
            value=9.999.967.363
        ==
    ==
  ::
  ++  decoded-tx
    ^-  data:tx:bolt
    :_  ws=~[~[witness-part-1 witness-part-2]]
    :*  is=decoded-inputs
        os=decoded-outputs
        locktime=0
        nversion=2
        segwit=(some 1)
    ==
  ::
  ++  input-txid
    ^-  hexb:bc
    :-  32
    0x6371.37c2.8d8f.a677.e75a.851f.a93a.7323.57f4.32ea.e311.6075.9eb2.774a.45d6.e8ca
  ::
  ++  output1-script-pubkey
    ^-  hexb:bc
    :-  34
    0x20.e7b0.b352.33c8.214a.a0e9.885f.9392.e5f1.e967.3a3b.9160.5a1c.1b29.5b45.4430.cc83

  ::
  ++  output2-script-pubkey
    ^-  hexb:bc
    :-  22
    0x14.503c.901b.fb25.268d.74a0.b4a4.0387.8215.4b8f.ad6a
  ::
  ++  witness-part-1
    ^-  hexb:bc
    :-  72
    0x3045.0221.0081.82e7.a153.8235.4a50.3913.85f2.
    9214.9f02.0e3f.b422.0f45.0e13.8d9b.32cf.999f.
    2002.203f.6135.1531.335b.3965.a166.d2b3.d47b.
    a909.ae1b.2c0c.5821.f293.40eb.31b4.6c06.2301
  ::
  ++  witness-part-2
    ^-  hexb:bc
    :-  33
    0x2.7dc3.13f1.aaa7.723f.2cab.b5fc.9a85.3d60.8b2e.ce4b.3eb3.ba1a.cb23.a742.9c15.fcc8
  ::
  ++  raw-tx
    ^-  hexb:bc
    :-  235
    0x2.0000.0000.0101.cae8.d645.4a77.b29e.7560.11e3.
    ea32.f457.2373.3aa9.1f85.5ae7.77a6.8f8d.c237.7163.
    0000.0000.0000.0000.0002.a861.0000.0000.0000.2200.
    20e7.b0b3.5233.c821.4aa0.e988.5f93.92e5.f1e9.673a.
    3b91.605a.1c1b.295b.4544.30cc.8383.640b.5402.0000.
    0016.0014.503c.901b.fb25.268d.74a0.b4a4.0387.8215.
    4b8f.ad6a.0248.3045.0221.0081.82e7.a153.8235.4a50.
    3913.85f2.9214.9f02.0e3f.b422.0f45.0e13.8d9b.32cf.
    999f.2002.203f.6135.1531.335b.3965.a166.d2b3.d47b.
    a909.ae1b.2c0c.5821.f293.40eb.31b4.6c06.2301.2102.
    7dc3.13f1.aaa7.723f.2cab.b5fc.9a85.3d60.8b2e.ce4b.
    3eb3.ba1a.cb23.a742.9c15.fcc8.0000.0000
  --
::
::  test vectors from https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#appendix-b-funding-transaction-test-vectors
::
++  test-funding-tx
  =,  bolt-tx:bolt
  |^
  ;:  weld
    check-witness-script
    check-funding-tx
  ==
  ::
  ++  check-witness-script
    %+  expect-eq
      !>  funding-witness-script
    !>  %-  en:btc-script
        %+  funding-output:script
          local-funding-pubkey
        remote-funding-pubkey
  ::
  ++  check-funding-tx
    %+  expect-eq
      !>  funding-tx
      !>  %-  segwit-encode:bitcoin-txu
          %:  funding-tx:bolt-tx:bolt
            lpk=local-funding-pubkey
            rpk=remote-funding-pubkey
            amt=10.000.000
            ins=funding-inputs
            chg=funding-change
            ws=~
          ==
  ::
  ++  privkey
    [33 0x6b.d078.650f.cee8.444e.4e09.8252.27b8.01a1.ca92.8deb.b750.eb36.e6d5.6124.bb20.e801]
  ::
  ++  local-funding-pubkey
    ^-  hexb:bc
    [33 0x2.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb]
  ::
  ++  remote-funding-pubkey
    ^-  hexb:bc
    [33 0x3.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1]
  ::
  ++  funding-tx
    ^-  hexb:bc
    :-  232
        0x200.0000.01ad.bb20.ea41.a842.3ea9.37e7.
    6e81.5163.6bf6.093b.70ea.ff94.2930.d205.7660.
    0521.fd00.0000.006b.4830.4502.2100.9058.7b62.
    01e1.66ad.6af0.227d.3036.a945.4223.d49a.1f11.
    839c.1a36.2184.340e.f024.0220.577f.7cd5.cca7.
    8719.405c.bf1d.e741.4ac0.27f0.239e.f6e2.14c9.
    0fca.ab04.54d8.4b3b.0121.0353.5b32.d5eb.0a6e.
    d098.2a04.79bb.adc9.868d.9836.f6ba.94dd.5a63.
    be16.d875.0691.84ff.ffff.ff02.8096.9800.0000.
    0000.2200.20c0.15c4.a6be.010e.2165.7068.fc2e.
    6a9d.02b2.7ebe.4d49.0a25.846f.7237.f104.d1a3.
    cd20.256d.2901.0000.0016.0014.3ca3.3c2e.4446.
    f4a3.05f2.3c80.df8a.d1af.dcf6.52f9.0000.0000
  ::
  ++  funding-witness-script
    ^-  hexb:bc
    :-  71
    0x52.2102.3da0.92f6.980e.58d2.c037.1731.80e9.
    a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.
    2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.
    504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae
  ::
  ++  input-txid
    ^-  hexb:bc
    :*  wid=32
        dat=0xfd21.0560.7605.d230.2994.ffea.703b.09f6.6b63.5181.6ee7.37a9.3e42.a841.ea20.bbad
    ==
  ::
  ++  funding-script-sig
    :*  wid=107
        dat=0x48.3045.0221.0090.587b.6201.e166.ad6a.f022.
            7d30.36a9.4542.23d4.9a1f.1183.9c1a.3621.8434.
            0ef0.2402.2057.7f7c.d5cc.a787.1940.5cbf.1de7.
            414a.c027.f023.9ef6.e214.c90f.caab.0454.d84b.
            3b01.2103.535b.32d5.eb0a.6ed0.982a.0479.bbad.
            c986.8d98.36f6.ba94.dd5a.63be.16d8.7506.9184
    ==
  ::
  ++  funding-inputs
    :~  :*  txid=input-txid
            pos=0
            sequence=[wid=4 dat=0xffff.ffff]
            script-sig=(some funding-script-sig)
            pubkey=~
            value=5.000.000.000
         ==
    ==
  ::
  ++  funding-change
    :*  script-pubkey=[wid=22 dat=0x14.3ca3.3c2e.4446.f4a3.05f2.3c80.df8a.d1af.dcf6.52f9]
        value=4.989.986.080
    ==
  --
::
::  test vectors from https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#appendix-c-commitment-and-htlc-transaction-test-vectors
::
++  tx-test
  |%
  ::
  ++  funding-txid
    ^-  hexb:bc
    :-  32
    0x8984.484a.580b.825b.9972.d7ad.b150.50b3.ab62.4ccd.7319.46b3.eedd.b92f.4e7e.f6be
  ::
  ++  funding-output-index  0
  ::
  ++  funding-amount  10.000.000
  ::
  ++  funding-outpoint
    ^-  outpoint:bolt
    :*  txid=funding-txid
        pos=funding-output-index
        sats=funding-amount
    ==
  ::
  ++  remote-funding-sig
    ^-  hexb:bc
    :-  72
    0x3045.0221.00f5.1d2e.566a.70ba.740f.c5d8.
      c0f0.7b9b.93d2.ed74.1c3c.0860.c613.173d.
      e7d3.9e79.6802.2041.376d.520e.9c0e.1ad5.
      2248.ddf4.b22e.12be.8763.007d.f977.253e.
      f45a.4ca3.bdb7.c001
  ::
  ++  local-funding-sig
    ^-  hexb:bc
    :-  71
    0x30.4402.2051.b75c.7319.8c6d.eee1.a875.
    871c.3961.8329.09ac.d297.c6b9.08d5.9e33.
    19e5.185a.4602.2055.c419.379c.5051.a78d.
    00db.bce1.1b5b.664a.0c22.815f.bcc6.fcef.
    6b19.37c3.8369.3901
  ::
  ++  local-funding-privkey
    ^-  hexb:bc
    :-  33
    0x30.ff49.56bb.dd32.22d4.4cc5.e8a1.261d.ab1e.0795.7bda.c5ae.88fe.3261.ef32.1f37.4901
  ::
  ++  local-funding-pubkey
    ^-  hexb:bc
    :-  33
    0x2.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb
  ::
  ++  remote-funding-pubkey
    ^-  hexb:bc
    :-  33
    0x3.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1
  ::
  ++  remote-pubkey
    ^-  hexb:bc
    :-  33
    0x3.9485.4aa6.eab5.b2a8.122c.c726.e9dd.ed05.3a21.84d8.8256.8168.26d6.231c.068d.4a5b
  ::
  ++  local-privkey
    ^-  hexb:bc
    :-  33
    0xbb.13b1.21cd.c357.cd2e.608b.0aea.294a.fca3.6e2b.34cf.958e.2e64.51a2.f274.6944.9101
  ::
  ++  local-pubkey
    ^-  hexb:bc
    :-  33
    0x3.0d41.7a46.9463.84f8.8d5f.3337.267c.5e57.9765.875d.c4da.ca81.3e21.734b.1406.39e7
  ::
  ++  local-delayed-pubkey
    ^-  hexb:bc
    :-  33
    0x3.fd59.6052.8dc1.5201.4952.efdb.702a.88f7.1e3c.1653.b231.4431.701e.c77e.57fd.e83c
  ::
  ++  local-revocation-pubkey
    ^-  hexb:bc
    :-  33
    0x2.12a1.40cd.0c65.39d0.7cd0.8dfe.0998.4dec.3251.ea80.8b89.2efe.ac3e.de94.02bf.2b19
  ::
  ++  local-payment-basepoint
    %-  decompress-point:secp256k1:secp:crypto
    0x3.4f35.5bdc.b7cc.0af7.28ef.3cce.b961.5d90.684b.b5b2.ca5f.859a.b0f0.b704.0758.71aa
  ::
  ++  remote-payment-basepoint
    %-  decompress-point:secp256k1:secp:crypto
    0x3.2c0b.7cf9.5324.a07d.0539.8b24.0174.dc0c.2be4.44d9.6b15.9aa6.c7f7.b1e6.6868.0991
  ::
  ++  keyring
    :*  local-htlc-key=local-pubkey
        remote-htlc-key=remote-pubkey
        to-local-key=local-delayed-pubkey
        to-remote-key=remote-pubkey
        revocation-key=local-revocation-pubkey
    ==
  ::
  ++  channel
    ^-  chan
    =|  ch=chan
    %_  ch
      initiator         %.y
      anchor-outputs    %.n
      dust-limit        546
      funding-outpoint  funding-outpoint
      funding-sats      funding-amount
      feerate-per-kw    0
      to-self-delay     144
      ::
      funding-pubkey.our  local-funding-pubkey
      funding-pubkey.her  remote-funding-pubkey
      ::
      funding-signature.our  local-funding-sig
      funding-signature.her  remote-funding-sig
      ::
      payment.basepoints.our  local-payment-basepoint
      payment.basepoints.her  remote-payment-basepoint
      ::
      commitment-number.commit-state.our  42
      commitment-number.commit-state.her  42
    ==
  ::
  +$  htlc-data
    $:  received=?
        id=@ud
        amount=msats
        preimage=hexb:bc
        expiry=@ud
    ==
  ::
  +$  test-vector
    $:  to-local-msat=msats
        to-remote-msat=msats
        htlcs=(list htlc-data)
        local-feerate-per-kw=@ud
        our-funding-signature=(unit signature)
        her-funding-signature=(unit signature)
        output-commit-tx=hexb:bc
    ==
  --
::
++  test-commitment-tx
  ^-  tang
  |^
  %-  zing
  (turn tx-test-vectors check-commitment)
  ::
  ++  check-commitment
    |=  =test-vector:tx-test
    =/  [received=(list htlc) offered=(list htlc)]
      %-  partition-htlcs
      htlcs.test-vector
    =+  c=channel:tx-test
    =:  feerate-per-kw.c             local-feerate-per-kw.test-vector
        received.commit-state.our.c  received
        offered.commit-state.our.c   offered
    ==
    ::
    =?  funding-signature.our.c  ?=(^ our-funding-signature.test-vector)
      u.our-funding-signature.test-vector
    ::
    =?  funding-signature.her.c  ?=(^ her-funding-signature.test-vector)
      u.her-funding-signature.test-vector
    ::
    %+  expect-eq
      !>  output-commit-tx.test-vector
      !>  %-  segwit-encode:bitcoin-txu:bolt
          %~  tx-data  commitment:bolt-tx:bolt
          :*
            c=c
            keyring=keyring:tx-test
            to-local=to-local-msat.test-vector
            to-remote=to-remote-msat.test-vector
            our=%.y
          ==
  ::
  ++  partition-htlcs
    |=  htlcs=(list htlc-data:tx-test)
    =/  [received=(list htlc-data:tx-test) offered=(list htlc-data:tx-test)]
      %+  skid  htlcs
      |=  h=htlc-data:tx-test
      received.h
    :-  (turn received create-htlc)
        (turn offered create-htlc)
  ::
  ++  create-htlc
    |=  h=htlc-data:tx-test
    ^-  htlc
    :*  from=~sampel-palnet
        id=id.h
        channel-id=0
        amount-msat=amount.h
        payment-hash=(sha256:bc preimage.h)
        cltv-expiry=expiry.h
    ==
  --
::
++  htlc-data
  ^-  (list htlc-data:tx-test)
  :~
    :*  received=%.y
        id=0
        amount=1.000.000
        preimage=[wid=32 dat=0x0]
        expiry=500
    ==
    ::
    :*  received=%.y
        id=1
        amount=2.000.000
        preimage=[wid=32 dat=0x101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101]
        expiry=501
    ==
    ::
    :*  received=%.n
        id=2
        amount=2.000.000
        preimage=[wid=32 dat=0x202.0202.0202.0202.0202.0202.0202.0202.0202.0202.0202.0202.0202.0202.0202.0202]
        expiry=502
    ==
    ::
    :*  received=%.n
        id=3
        amount=3.000.000
        preimage=[wid=32 dat=0x303.0303.0303.0303.0303.0303.0303.0303.0303.0303.0303.0303.0303.0303.0303.0303]
        expiry=503
    ==
    ::
    :*  received=%.y
        id=4
        amount=4.000.000
        preimage=[wid=32 dat=0x404.0404.0404.0404.0404.0404.0404.0404.0404.0404.0404.0404.0404.0404.0404.0404]
        expiry=504
    ==
  ==
::
++  htlc-data-2
  ^-  (list htlc-data:tx-test)
  :~
    :*  received=%.y
        id=1
        amount=2.000.000
        preimage=[wid=32 dat=0x101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101]
        expiry=501
    ==
    ::
    :*  received=%.n
        id=5
        amount=5.000.000
        preimage=[wid=32 dat=0x505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505]
        expiry=506
    ==
    ::
    :*  received=%.n
        id=6
        amount=5.000.001
        preimage=[wid=32 dat=0x505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505.0505]
        expiry=505
    ==
  ==
::
++  tx-test-vectors
  ^-  (list test-vector:tx-test)
  :~
    :*  to-local-msat=7.000.000.000
        to-remote-msat=3.000.000.000
        htlcs=~
        local-feerate-per-kw=15.000
        our-funding-signature=~
        her-funding-signature=~
        output-commit-tx=[346 0x200.0000.0001.01be.f67e.4e2f.b9dd.eeb3.4619.73cd.4c62.abb3.5050.b1ad.d772.995b.820b.584a.4884.8900.0000.0000.38b0.2b80.02c0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.54a5.6a00.0000.0000.2200.204a.db4e.2f00.643d.b396.dd12.0d4e.7dc1.7625.f5f2.c11a.40d8.57ac.cc86.2d6b.7dd8.0e04.0047.3044.0220.51b7.5c73.198c.6dee.e1a8.7587.1c39.6183.2909.acd2.97c6.b908.d59e.3319.e518.5a46.0220.55c4.1937.9c50.51a7.8d00.dbbc.e11b.5b66.4a0c.2281.5fbc.c6fc.ef6b.1937.c383.6939.0148.3045.0221.00f5.1d2e.566a.70ba.740f.c5d8.c0f0.7b9b.93d2.ed74.1c3c.0860.c613.173d.e7d3.9e79.6802.2041.376d.520e.9c0e.1ad5.2248.ddf4.b22e.12be.8763.007d.f977.253e.f45a.4ca3.bdb7.c001.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=0
        our-funding-signature=(some [71 0x30.4402.2027.5b0c.325a.5e93.5565.0dc3.0c0e.ccfb.c7ef.b239.87c2.4b55.6b9d.fdd4.0eff.ca18.d202.206c.aceb.2c06.7836.c51f.2967.40c7.ae80.7ffc.bfbf.1dd3.a0d5.6b6d.e9a5.b247.985f.0601])
        her-funding-signature=(some [71 0x30.4402.204f.d492.8835.db1c.cdfc.40f5.c78c.e9bd.6524.9b16.348d.f81f.0c44.328d.cdef.c97d.6302.2019.4d38.69c3.8bc7.32dd.87d1.3d29.5801.5e2f.c168.29e7.4cd4.377f.84d2.15c0.b706.0601])
        output-commit-tx=[560 0x200.0000.0001.01be.f67e.4e2f.b9dd.eeb3.4619.73cd.4c62.abb3.5050.b1ad.d772.995b.820b.584a.4884.8900.0000.0000.38b0.2b80.07e8.0300.0000.0000.0022.0020.52bf.ef04.79d7.b293.c27e.0f1e.b294.bea1.54c6.3a32.94ef.092c.19af.5140.9bce.0e2a.d007.0000.0000.0000.2200.2040.3d39.4747.cae4.2e98.ff01.734a.d5c0.8f82.ba12.3d3d.9a62.0abd.a889.8965.1e2a.b5d0.0700.0000.0000.0022.0020.748e.ba94.4fed.c882.7f6b.06bc.4467.8f93.c0f9.e607.8b35.c633.1ed3.1e75.f8ce.0c2d.b80b.0000.0000.0000.2200.20c2.0b5d.1f85.84fd.9044.3e7b.7b72.0136.174f.a4b9.333c.261d.04db.bd01.2635.c0f4.19a0.0f00.0000.0000.0022.0020.8c48.d151.6039.7c97.31df.9bc3.b236.656e.fb66.65fb.fe92.b4a6.878e.88a4.99f7.41c4.c0c6.2d00.0000.0000.1600.14cc.f1af.2f2a.abee.14bb.40fa.3851.ab23.01de.8431.10e0.a06a.0000.0000.0022.0020.4adb.4e2f.0064.3db3.96dd.120d.4e7d.c176.25f5.f2c1.1a40.d857.accc.862d.6b7d.d80e.0400.4730.4402.2027.5b0c.325a.5e93.5565.0dc3.0c0e.ccfb.c7ef.b239.87c2.4b55.6b9d.fdd4.0eff.ca18.d202.206c.aceb.2c06.7836.c51f.2967.40c7.ae80.7ffc.bfbf.1dd3.a0d5.6b6d.e9a5.b247.985f.0601.4730.4402.204f.d492.8835.db1c.cdfc.40f5.c78c.e9bd.6524.9b16.348d.f81f.0c44.328d.cdef.c97d.6302.2019.4d38.69c3.8bc7.32dd.87d1.3d29.5801.5e2f.c168.29e7.4cd4.377f.84d2.15c0.b706.0601.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=647
        our-funding-signature=(some [72 0x3045.0221.0094.bfd8.f557.2ac0.157e.c76a.9551.b6c5.216a.4538.c07c.d13a.51af.4a54.cb26.fa14.3202.2076.8efc.e8ce.6f4a.5efa.c875.142f.f192.37c0.1134.3670.adf9.c7ac.6970.4a12.0d11.6301])
        her-funding-signature=(some [72 0x3045.0221.00a5.c013.83d3.ec64.6d97.e40f.4431.8d49.def8.17fc.d61a.0ef1.8008.a665.b3e1.5178.5502.203e.648e.fddd.5838.981e.f55e.c954.be69.c4a6.52d0.21e6.081a.100d.034d.e366.815e.9b01])
        output-commit-tx=[562 0x200.0000.0001.01be.f67e.4e2f.b9dd.eeb3.4619.73cd.4c62.abb3.5050.b1ad.d772.995b.820b.584a.4884.8900.0000.0000.38b0.2b80.07e8.0300.0000.0000.0022.0020.52bf.ef04.79d7.b293.c27e.0f1e.b294.bea1.54c6.3a32.94ef.092c.19af.5140.9bce.0e2a.d007.0000.0000.0000.2200.2040.3d39.4747.cae4.2e98.ff01.734a.d5c0.8f82.ba12.3d3d.9a62.0abd.a889.8965.1e2a.b5d0.0700.0000.0000.0022.0020.748e.ba94.4fed.c882.7f6b.06bc.4467.8f93.c0f9.e607.8b35.c633.1ed3.1e75.f8ce.0c2d.b80b.0000.0000.0000.2200.20c2.0b5d.1f85.84fd.9044.3e7b.7b72.0136.174f.a4b9.333c.261d.04db.bd01.2635.c0f4.19a0.0f00.0000.0000.0022.0020.8c48.d151.6039.7c97.31df.9bc3.b236.656e.fb66.65fb.fe92.b4a6.878e.88a4.99f7.41c4.c0c6.2d00.0000.0000.1600.14cc.f1af.2f2a.abee.14bb.40fa.3851.ab23.01de.8431.10e0.9c6a.0000.0000.0022.0020.4adb.4e2f.0064.3db3.96dd.120d.4e7d.c176.25f5.f2c1.1a40.d857.accc.862d.6b7d.d80e.0400.4830.4502.2100.94bf.d8f5.572a.c015.7ec7.6a95.51b6.c521.6a45.38c0.7cd1.3a51.af4a.54cb.26fa.1432.0220.768e.fce8.ce6f.4a5e.fac8.7514.2ff1.9237.c011.3436.70ad.f9c7.ac69.704a.120d.1163.0148.3045.0221.00a5.c013.83d3.ec64.6d97.e40f.4431.8d49.def8.17fc.d61a.0ef1.8008.a665.b3e1.5178.5502.203e.648e.fddd.5838.981e.f55e.c954.be69.c4a6.52d0.21e6.081a.100d.034d.e366.815e.9b01.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=648
        our-funding-signature=(some [72 0x3045.0221.00a2.270d.5950.c89a.e084.1233.f6ef.ea9c.9518.98b3.01b2.e89e.0adb.d2c6.87b9.f32e.fa02.2079.43d9.0f95.b961.0458.e7c6.5a57.6e14.9750.ff3a.ccaa.cad0.04cd.85e7.0b23.5e27.de01])
        her-funding-signature=(some [71 0x30.4402.2072.714e.2fbb.93cd.d1c4.2eb0.828b.4f2e.ff14.3f71.7d8f.26e7.9d6a.da4f.0dcb.681b.be02.2009.11be.4e51.61dd.6ebe.59ff.1c58.e199.7c4a.ea80.4f81.db6b.6988.21db.6093.d7b0.5701])
        output-commit-tx=[518 0x200.0000.0001.01be.f67e.4e2f.b9dd.eeb3.4619.73cd.4c62.abb3.5050.b1ad.d772.995b.820b.584a.4884.8900.0000.0000.38b0.2b80.06d0.0700.0000.0000.0022.0020.403d.3947.47ca.e42e.98ff.0173.4ad5.c08f.82ba.123d.3d9a.620a.bda8.8989.651e.2ab5.d007.0000.0000.0000.2200.2074.8eba.944f.edc8.827f.6b06.bc44.678f.93c0.f9e6.078b.35c6.331e.d31e.75f8.ce0c.2db8.0b00.0000.0000.0022.0020.c20b.5d1f.8584.fd90.443e.7b7b.7201.3617.4fa4.b933.3c26.1d04.dbbd.0126.35c0.f419.a00f.0000.0000.0000.2200.208c.48d1.5160.397c.9731.df9b.c3b2.3665.6efb.6665.fbfe.92b4.a687.8e88.a499.f741.c4c0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.4e9d.6a00.0000.0000.2200.204a.db4e.2f00.643d.b396.dd12.0d4e.7dc1.7625.f5f2.c11a.40d8.57ac.cc86.2d6b.7dd8.0e04.0048.3045.0221.00a2.270d.5950.c89a.e084.1233.f6ef.ea9c.9518.98b3.01b2.e89e.0adb.d2c6.87b9.f32e.fa02.2079.43d9.0f95.b961.0458.e7c6.5a57.6e14.9750.ff3a.ccaa.cad0.04cd.85e7.0b23.5e27.de01.4730.4402.2072.714e.2fbb.93cd.d1c4.2eb0.828b.4f2e.ff14.3f71.7d8f.26e7.9d6a.da4f.0dcb.681b.be02.2009.11be.4e51.61dd.6ebe.59ff.1c58.e199.7c4a.ea80.4f81.db6b.6988.21db.6093.d7b0.5701.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=2.069
        our-funding-signature=(some [71 0x30.4402.203c.a8f3.1c6a.4751.9f83.255d.c69f.1894.d9a6.d747.6a19.f498.d31e.af0c.d3a8.5eeb.6302.2026.fd92.dc75.2b33.905c.4c83.8c52.8b69.2a8a.d4ce.d959.990b.5d5e.e2ff.940f.a90e.ea01])
        her-funding-signature=(some [71 0x30.4402.2001.d55e.488b.8b03.5b2d.d29d.50b6.5b53.0923.a416.d47f.3772.8414.5bc8.767b.1b6a.7502.2019.bb53.ddfe.1cef.af15.6f92.4777.eaaf.8fdc.a181.0695.a7d0.a247.ad2a.fba8.232e.b401])
        output-commit-tx=[517 0x2.0000.0000.0101.bef6.7e4e.2fb9.ddee.b346.1973.cd4c.62ab.b350.50b1.add7.7299.5b82.0b58.4a48.8489.0000.0000.0038.b02b.8006.d007.0000.0000.0000.2200.2040.3d39.4747.cae4.2e98.ff01.734a.d5c0.8f82.ba12.3d3d.9a62.0abd.a889.8965.1e2a.b5d0.0700.0000.0000.0022.0020.748e.ba94.4fed.c882.7f6b.06bc.4467.8f93.c0f9.e607.8b35.c633.1ed3.1e75.f8ce.0c2d.b80b.0000.0000.0000.2200.20c2.0b5d.1f85.84fd.9044.3e7b.7b72.0136.174f.a4b9.333c.261d.04db.bd01.2635.c0f4.19a0.0f00.0000.0000.0022.0020.8c48.d151.6039.7c97.31df.9bc3.b236.656e.fb66.65fb.fe92.b4a6.878e.88a4.99f7.41c4.c0c6.2d00.0000.0000.1600.14cc.f1af.2f2a.abee.14bb.40fa.3851.ab23.01de.8431.1077.956a.0000.0000.0022.0020.4adb.4e2f.0064.3db3.96dd.120d.4e7d.c176.25f5.f2c1.1a40.d857.accc.862d.6b7d.d80e.0400.4730.4402.203c.a8f3.1c6a.4751.9f83.255d.c69f.1894.d9a6.d747.6a19.f498.d31e.af0c.d3a8.5eeb.6302.2026.fd92.dc75.2b33.905c.4c83.8c52.8b69.2a8a.d4ce.d959.990b.5d5e.e2ff.940f.a90e.ea01.4730.4402.2001.d55e.488b.8b03.5b2d.d29d.50b6.5b53.0923.a416.d47f.3772.8414.5bc8.767b.1b6a.7502.2019.bb53.ddfe.1cef.af15.6f92.4777.eaaf.8fdc.a181.0695.a7d0.a247.ad2a.fba8.232e.b401.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=2.070
        our-funding-signature=(some [71 0x30.4402.2044.3cb0.7f65.0aeb.bba1.4b8b.c8d8.1e09.6712.590f.524c.5991.ac0e.d3bb.c8fd.3bd0.c702.2028.a635.f548.e3ca.64b1.9b69.b1ea.00f0.5b22.752f.91da.f0b6.dab7.8e62.ba52.eb7f.d001])
        her-funding-signature=(some [72 0x3045.0221.00f2.377f.7a67.b7fc.7f4e.2c0c.9e3a.7de9.35c3.2417.f566.8eda.31ea.1db4.01b7.dc53.0302.2041.5fdb.c8e9.1d0f.735e.70c2.1952.3427.42e2.5249.b0d0.62d4.3efb.fc56.4499.f375.2601])
        output-commit-tx=[475 0x2.0000.0000.0101.bef6.7e4e.2fb9.ddee.b346.1973.cd4c.62ab.b350.50b1.add7.7299.5b82.0b58.4a48.8489.0000.0000.0038.b02b.8005.d007.0000.0000.0000.2200.2040.3d39.4747.cae4.2e98.ff01.734a.d5c0.8f82.ba12.3d3d.9a62.0abd.a889.8965.1e2a.b5b8.0b00.0000.0000.0022.0020.c20b.5d1f.8584.fd90.443e.7b7b.7201.3617.4fa4.b933.3c26.1d04.dbbd.0126.35c0.f419.a00f.0000.0000.0000.2200.208c.48d1.5160.397c.9731.df9b.c3b2.3665.6efb.6665.fbfe.92b4.a687.8e88.a499.f741.c4c0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.da96.6a00.0000.0000.2200.204a.db4e.2f00.643d.b396.dd12.0d4e.7dc1.7625.f5f2.c11a.40d8.57ac.cc86.2d6b.7dd8.0e04.0047.3044.0220.443c.b07f.650a.ebbb.a14b.8bc8.d81e.0967.1259.0f52.4c59.91ac.0ed3.bbc8.fd3b.d0c7.0220.28a6.35f5.48e3.ca64.b19b.69b1.ea00.f05b.2275.2f91.daf0.b6da.b78e.62ba.52eb.7fd0.0148.3045.0221.00f2.377f.7a67.b7fc.7f4e.2c0c.9e3a.7de9.35c3.2417.f566.8eda.31ea.1db4.01b7.dc53.0302.2041.5fdb.c8e9.1d0f.735e.70c2.1952.3427.42e2.5249.b0d0.62d4.3efb.fc56.4499.f375.2601.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=2.194
        our-funding-signature=(some [71 0x30.4402.203b.1b01.0c10.9c2e.cbe7.feb2.d259.b9c4.126b.d5dc.99ee.693c.422e.c0a5.781f.e161.ba02.2057.1fe4.e2c6.49de.a9c7.aaf7.e49b.3829.62f6.a349.4963.c97d.80fe.f9a4.30ca.3f70.6101])
        her-funding-signature=(some [72 0x3045.0221.00d3.3c4e.541a.a1d2.55d4.1ea9.a3b4.43b3.b822.ad8f.7f86.8626.38aa.c1f6.9f8f.7605.7702.2007.e2a1.8e69.31ce.3d3a.804b.1c78.eda1.de17.dbe1.fb7a.9548.8c9a.4ec8.6203.9533.4801])
        output-commit-tx=[475 0x2.0000.0000.0101.bef6.7e4e.2fb9.ddee.b346.1973.cd4c.62ab.b350.50b1.add7.7299.5b82.0b58.4a48.8489.0000.0000.0038.b02b.8005.d007.0000.0000.0000.2200.2040.3d39.4747.cae4.2e98.ff01.734a.d5c0.8f82.ba12.3d3d.9a62.0abd.a889.8965.1e2a.b5b8.0b00.0000.0000.0022.0020.c20b.5d1f.8584.fd90.443e.7b7b.7201.3617.4fa4.b933.3c26.1d04.dbbd.0126.35c0.f419.a00f.0000.0000.0000.2200.208c.48d1.5160.397c.9731.df9b.c3b2.3665.6efb.6665.fbfe.92b4.a687.8e88.a499.f741.c4c0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.4096.6a00.0000.0000.2200.204a.db4e.2f00.643d.b396.dd12.0d4e.7dc1.7625.f5f2.c11a.40d8.57ac.cc86.2d6b.7dd8.0e04.0047.3044.0220.3b1b.010c.109c.2ecb.e7fe.b2d2.59b9.c412.6bd5.dc99.ee69.3c42.2ec0.a578.1fe1.61ba.0220.571f.e4e2.c649.dea9.c7aa.f7e4.9b38.2962.f6a3.4949.63c9.7d80.fef9.a430.ca3f.7061.0148.3045.0221.00d3.3c4e.541a.a1d2.55d4.1ea9.a3b4.43b3.b822.ad8f.7f86.8626.38aa.c1f6.9f8f.7605.7702.2007.e2a1.8e69.31ce.3d3a.804b.1c78.eda1.de17.dbe1.fb7a.9548.8c9a.4ec8.6203.9533.4801.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=2.195
        our-funding-signature=(some [71 0x30.4402.203b.12d4.4254.244b.8ff3.bb41.29b0.920f.d451.20ab.42f5.53d9.9763.94b0.99d5.00c9.9e02.205e.95bb.7a31.6485.2ef0.c48f.9e0e.af14.5218.f8e2.c412.51b2.31f0.3cbd.c4f2.9a54.2901])
        her-funding-signature=(some [71 0x30.4402.205e.2f76.d465.7fb7.32c0.dfc8.20a1.8a73.01e3.68f5.799e.06b7.8280.0763.3741.bda6.df02.2045.8009.ae59.d0c6.2460.65c4.1935.9e05.eb2a.4b4e.f4a1.b310.cc91.2db4.4eb7.9242.9801])
        output-commit-tx=[431 0x2.0000.0000.0101.bef6.7e4e.2fb9.ddee.b346.1973.cd4c.62ab.b350.50b1.add7.7299.5b82.0b58.4a48.8489.0000.0000.0038.b02b.8004.b80b.0000.0000.0000.2200.20c2.0b5d.1f85.84fd.9044.3e7b.7b72.0136.174f.a4b9.333c.261d.04db.bd01.2635.c0f4.19a0.0f00.0000.0000.0022.0020.8c48.d151.6039.7c97.31df.9bc3.b236.656e.fb66.65fb.fe92.b4a6.878e.88a4.99f7.41c4.c0c6.2d00.0000.0000.1600.14cc.f1af.2f2a.abee.14bb.40fa.3851.ab23.01de.8431.10b8.976a.0000.0000.0022.0020.4adb.4e2f.0064.3db3.96dd.120d.4e7d.c176.25f5.f2c1.1a40.d857.accc.862d.6b7d.d80e.0400.4730.4402.203b.12d4.4254.244b.8ff3.bb41.29b0.920f.d451.20ab.42f5.53d9.9763.94b0.99d5.00c9.9e02.205e.95bb.7a31.6485.2ef0.c48f.9e0e.af14.5218.f8e2.c412.51b2.31f0.3cbd.c4f2.9a54.2901.4730.4402.205e.2f76.d465.7fb7.32c0.dfc8.20a1.8a73.01e3.68f5.799e.06b7.8280.0763.3741.bda6.df02.2045.8009.ae59.d0c6.2460.65c4.1935.9e05.eb2a.4b4e.f4a1.b310.cc91.2db4.4eb7.9242.9801.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=3.702
        our-funding-signature=(some [71 0x30.4402.200e.930a.43c7.9511.62dc.15a2.b734.4f48.091c.74c7.0f70.24e7.116e.900d.8bcf.ba86.1c02.2066.fa6c.bda3.929e.21da.a2e7.e16a.4b94.8db7.e891.9ef9.7840.2360.d109.5ffd.aff7.b001])
        her-funding-signature=(some [72 0x3045.0221.00c1.a3b0.b60c.a092.ed50.8012.1f26.a74a.20ce.c6bd.ee3f.8e47.bae9.73fc.dceb.3eda.5502.207d.467a.9873.c939.bf3a.a758.014a.e672.95fe.dbca.5241.2633.f7e5.b267.0fc7.c381.c101])
        output-commit-tx=[432 0x200.0000.0001.01be.f67e.4e2f.b9dd.eeb3.4619.73cd.4c62.abb3.5050.b1ad.d772.995b.820b.584a.4884.8900.0000.0000.38b0.2b80.04b8.0b00.0000.0000.0022.0020.c20b.5d1f.8584.fd90.443e.7b7b.7201.3617.4fa4.b933.3c26.1d04.dbbd.0126.35c0.f419.a00f.0000.0000.0000.2200.208c.48d1.5160.397c.9731.df9b.c3b2.3665.6efb.6665.fbfe.92b4.a687.8e88.a499.f741.c4c0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.6f91.6a00.0000.0000.2200.204a.db4e.2f00.643d.b396.dd12.0d4e.7dc1.7625.f5f2.c11a.40d8.57ac.cc86.2d6b.7dd8.0e04.0047.3044.0220.0e93.0a43.c795.1162.dc15.a2b7.344f.4809.1c74.c70f.7024.e711.6e90.0d8b.cfba.861c.0220.66fa.6cbd.a392.9e21.daa2.e7e1.6a4b.948d.b7e8.919e.f978.4023.60d1.095f.fdaf.f7b0.0148.3045.0221.00c1.a3b0.b60c.a092.ed50.8012.1f26.a74a.20ce.c6bd.ee3f.8e47.bae9.73fc.dceb.3eda.5502.207d.467a.9873.c939.bf3a.a758.014a.e672.95fe.dbca.5241.2633.f7e5.b267.0fc7.c381.c101.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=3.703
        our-funding-signature=(some [71 0x30.4402.2047.3055.31dd.4439.1dce.03ae.20f8.7350.05c6.15eb.077a.974e.db00.59ea.1a31.1857.d602.202e.0ed6.972f.bdd1.e8cb.542b.06e0.929b.c41b.2ddf.236e.04cb.75ed.d561.51f4.1975.0601])
        her-funding-signature=(some [72 0x3045.0221.008b.7c19.1dd4.6893.b67b.628e.618d.2dc8.e811.69d3.8bad.e310.181a.b77d.7c94.c667.5e02.203b.4dd1.31fd.7c9d.eb29.9560.983d.cdc4.8554.5c98.f989.f7ae.8180.c282.89f9.e6bd.b001])
        output-commit-tx=[389 0x2.0000.0000.0101.bef6.7e4e.2fb9.ddee.b346.1973.cd4c.62ab.b350.50b1.add7.7299.5b82.0b58.4a48.8489.0000.0000.0038.b02b.8003.a00f.0000.0000.0000.2200.208c.48d1.5160.397c.9731.df9b.c3b2.3665.6efb.6665.fbfe.92b4.a687.8e88.a499.f741.c4c0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.eb93.6a00.0000.0000.2200.204a.db4e.2f00.643d.b396.dd12.0d4e.7dc1.7625.f5f2.c11a.40d8.57ac.cc86.2d6b.7dd8.0e04.0047.3044.0220.4730.5531.dd44.391d.ce03.ae20.f873.5005.c615.eb07.7a97.4edb.0059.ea1a.3118.57d6.0220.2e0e.d697.2fbd.d1e8.cb54.2b06.e092.9bc4.1b2d.df23.6e04.cb75.edd5.6151.f419.7506.0148.3045.0221.008b.7c19.1dd4.6893.b67b.628e.618d.2dc8.e811.69d3.8bad.e310.181a.b77d.7c94.c667.5e02.203b.4dd1.31fd.7c9d.eb29.9560.983d.cdc4.8554.5c98.f989.f7ae.8180.c282.89f9.e6bd.b001.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=4.914
        our-funding-signature=(some [71 0x30.4402.206a.2679.efa3.c7aa.ffd2.a447.fd0d.f7ab.a879.2858.b589.750f.6a12.03f9.2591.7319.8a02.2008.d52a.0e77.a99a.b533.c362.06cb.15ad.7aeb.2aa7.2b93.d4b5.71e7.28cb.5ec2.f6fe.2601])
        her-funding-signature=(some [71 0x30.4402.206d.6cb9.3969.d391.77a0.9d5d.45b5.83f3.4966.195b.77c7.e585.cf47.ac5c.ce0c.90ce.fb02.2031.d71a.e4e3.3a4e.80df.7f98.1d69.6fbd.ee51.7337.806a.3c71.38b7.491e.2cbb.077a.0e01])
        output-commit-tx=[388 0x200.0000.0001.01be.f67e.4e2f.b9dd.eeb3.4619.73cd.4c62.abb3.5050.b1ad.d772.995b.820b.584a.4884.8900.0000.0000.38b0.2b80.03a0.0f00.0000.0000.0022.0020.8c48.d151.6039.7c97.31df.9bc3.b236.656e.fb66.65fb.fe92.b4a6.878e.88a4.99f7.41c4.c0c6.2d00.0000.0000.1600.14cc.f1af.2f2a.abee.14bb.40fa.3851.ab23.01de.8431.10ae.8f6a.0000.0000.0022.0020.4adb.4e2f.0064.3db3.96dd.120d.4e7d.c176.25f5.f2c1.1a40.d857.accc.862d.6b7d.d80e.0400.4730.4402.206a.2679.efa3.c7aa.ffd2.a447.fd0d.f7ab.a879.2858.b589.750f.6a12.03f9.2591.7319.8a02.2008.d52a.0e77.a99a.b533.c362.06cb.15ad.7aeb.2aa7.2b93.d4b5.71e7.28cb.5ec2.f6fe.2601.4730.4402.206d.6cb9.3969.d391.77a0.9d5d.45b5.83f3.4966.195b.77c7.e585.cf47.ac5c.ce0c.90ce.fb02.2031.d71a.e4e3.3a4e.80df.7f98.1d69.6fbd.ee51.7337.806a.3c71.38b7.491e.2cbb.077a.0e01.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=4.915
        our-funding-signature=(some [72 0x3045.0221.00a0.1269.1ba6.cea2.f73f.a8ba.c377.5047.7e66.363c.6d28.813b.0bb6.da77.c8eb.3fb0.2702.2036.5e99.c513.04b0.b1a6.ab9e.a1c8.500d.b186.693e.39ec.1ad5.743e.e231.b013.8384.b901])
        her-funding-signature=(some [71 0x30.4402.2007.69ba.89c7.330d.fa4f.eba4.47b6.e322.305f.12ac.7dac.70ec.6ba9.97ed.7c1b.598d.0802.204f.e8d3.37e7.fee7.81f9.b7b1.a06e.580b.22f4.f79d.7400.5956.0191.d7db.53f8.7655.5201])
        output-commit-tx=[346 0x200.0000.0001.01be.f67e.4e2f.b9dd.eeb3.4619.73cd.4c62.abb3.5050.b1ad.d772.995b.820b.584a.4884.8900.0000.0000.38b0.2b80.02c0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.fa92.6a00.0000.0000.2200.204a.db4e.2f00.643d.b396.dd12.0d4e.7dc1.7625.f5f2.c11a.40d8.57ac.cc86.2d6b.7dd8.0e04.0048.3045.0221.00a0.1269.1ba6.cea2.f73f.a8ba.c377.5047.7e66.363c.6d28.813b.0bb6.da77.c8eb.3fb0.2702.2036.5e99.c513.04b0.b1a6.ab9e.a1c8.500d.b186.693e.39ec.1ad5.743e.e231.b013.8384.b901.4730.4402.2007.69ba.89c7.330d.fa4f.eba4.47b6.e322.305f.12ac.7dac.70ec.6ba9.97ed.7c1b.598d.0802.204f.e8d3.37e7.fee7.81f9.b7b1.a06e.580b.22f4.f79d.7400.5956.0191.d7db.53f8.7655.5201.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=9.651.180
        our-funding-signature=(some [71 0x30.4402.2051.4f97.7bf7.edc4.42de.8ce4.3ace.9686.e5eb.dc0f.8930.33f1.3e40.fb46.c8b8.c6e1.f902.2018.8006.227d.175f.5c35.da0b.092c.57be.a825.37ae.d89f.7778.204d.c5ba.cf4f.29f2.b901])
        her-funding-signature=(some [71 0x30.4402.2037.f83f.f00c.8e5f.b18a.e1f9.18ff.c24e.5458.1775.a20f.f1ae.7192.97ef.066c.71ca.a902.2039.c529.cccd.89ff.6c5e.d1db.7996.1453.3844.bd6d.101d.a503.761c.45c7.1399.6e3b.bd01])
        output-commit-tx=[345 0x2.0000.0000.0101.bef6.7e4e.2fb9.ddee.b346.1973.cd4c.62ab.b350.50b1.add7.7299.5b82.0b58.4a48.8489.0000.0000.0038.b02b.8002.2202.0000.0000.0000.2200.204a.db4e.2f00.643d.b396.dd12.0d4e.7dc1.7625.f5f2.c11a.40d8.57ac.cc86.2d6b.7dd8.0ec0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.0400.4730.4402.2051.4f97.7bf7.edc4.42de.8ce4.3ace.9686.e5eb.dc0f.8930.33f1.3e40.fb46.c8b8.c6e1.f902.2018.8006.227d.175f.5c35.da0b.092c.57be.a825.37ae.d89f.7778.204d.c5ba.cf4f.29f2.b901.4730.4402.2037.f83f.f00c.8e5f.b18a.e1f9.18ff.c24e.5458.1775.a20f.f1ae.7192.97ef.066c.71ca.a902.2039.c529.cccd.89ff.6c5e.d1db.7996.1453.3844.bd6d.101d.a503.761c.45c7.1399.6e3b.bd01.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=9.651.181
        our-funding-signature=(some [71 0x30.4402.2031.a82b.51bd.0149.15fe.6892.8d1a.bf4b.9885.353f.b896.cac1.0c3f.dd88.d7f9.c7f2.e002.2071.6bda.8196.41d2.c63e.65d3.549b.6120.112e.1aea.f174.2eed.94a4.7148.8e79.e206.b101])
        her-funding-signature=(some [71 0x30.4402.2064.9019.50be.922e.62cb.e3f2.ab93.de2b.99f3.7cff.9fc4.73e7.3e39.4b27.f88e.f073.1d02.206d.1dfa.2275.27b4.df44.a075.9928.9e20.7d6f.d9cc.a60c.0365.682d.cd3d.eaf7.3956.7e01])
        output-commit-tx=[302 0x200.0000.0001.01be.f67e.4e2f.b9dd.eeb3.4619.73cd.4c62.abb3.5050.b1ad.d772.995b.820b.584a.4884.8900.0000.0000.38b0.2b80.01c0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.0400.4730.4402.2031.a82b.51bd.0149.15fe.6892.8d1a.bf4b.9885.353f.b896.cac1.0c3f.dd88.d7f9.c7f2.e002.2071.6bda.8196.41d2.c63e.65d3.549b.6120.112e.1aea.f174.2eed.94a4.7148.8e79.e206.b101.4730.4402.2064.9019.50be.922e.62cb.e3f2.ab93.de2b.99f3.7cff.9fc4.73e7.3e39.4b27.f88e.f073.1d02.206d.1dfa.2275.27b4.df44.a075.9928.9e20.7d6f.d9cc.a60c.0365.682d.cd3d.eaf7.3956.7e01.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data
        local-feerate-per-kw=9.651.936
        our-funding-signature=(some [71 0x30.4402.2031.a82b.51bd.0149.15fe.6892.8d1a.bf4b.9885.353f.b896.cac1.0c3f.dd88.d7f9.c7f2.e002.2071.6bda.8196.41d2.c63e.65d3.549b.6120.112e.1aea.f174.2eed.94a4.7148.8e79.e206.b101])
        her-funding-signature=(some [71 0x30.4402.2064.9019.50be.922e.62cb.e3f2.ab93.de2b.99f3.7cff.9fc4.73e7.3e39.4b27.f88e.f073.1d02.206d.1dfa.2275.27b4.df44.a075.9928.9e20.7d6f.d9cc.a60c.0365.682d.cd3d.eaf7.3956.7e01])
        output-commit-tx=[302 0x200.0000.0001.01be.f67e.4e2f.b9dd.eeb3.4619.73cd.4c62.abb3.5050.b1ad.d772.995b.820b.584a.4884.8900.0000.0000.38b0.2b80.01c0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.0400.4730.4402.2031.a82b.51bd.0149.15fe.6892.8d1a.bf4b.9885.353f.b896.cac1.0c3f.dd88.d7f9.c7f2.e002.2071.6bda.8196.41d2.c63e.65d3.549b.6120.112e.1aea.f174.2eed.94a4.7148.8e79.e206.b101.4730.4402.2064.9019.50be.922e.62cb.e3f2.ab93.de2b.99f3.7cff.9fc4.73e7.3e39.4b27.f88e.f073.1d02.206d.1dfa.2275.27b4.df44.a075.9928.9e20.7d6f.d9cc.a60c.0365.682d.cd3d.eaf7.3956.7e01.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
    ::
    :*  to-local-msat=6.988.000.000
        to-remote-msat=3.000.000.000
        htlcs=htlc-data-2
        local-feerate-per-kw=253
        our-funding-signature=(some [72 0x3045.0221.0098.6746.86a1.3c7d.a2d9.5abe.a08d.27e9.3245.7315.6d79.e5eb.08cd.96d1.e33b.b004.5002.2063.9121.6f4f.d5fb.7b0f.e8c4.3074.fd19.f485.dd47.d7b0.7f73.25c5.a612.1f5b.0a59.1b01])
        her-funding-signature=(some [71 0x30.4402.2044.f807.aefa.4148.0a5d.1df2.fc31.2c48.6900.617f.d244.93cf.4197.6428.cb24.9ec2.c202.2007.fd12.29cf.b57d.638b.9c13.7b03.bc79.17d0.e418.b63e.62a3.642f.1c13.354c.c71d.f801])
        output-commit-tx=[475 0x2.0000.0000.0101.bef6.7e4e.2fb9.ddee.b346.1973.cd4c.62ab.b350.50b1.add7.7299.5b82.0b58.4a48.8489.0000.0000.0038.b02b.8005.d007.0000.0000.0000.2200.2074.8eba.944f.edc8.827f.6b06.bc44.678f.93c0.f9e6.078b.35c6.331e.d31e.75f8.ce0c.2d88.1300.0000.0000.0022.0020.305c.12e1.a0bc.21e2.83c1.31ce.a1c6.6d68.857d.28b7.b2fc.e0a6.fbc4.0c16.4852.121b.8813.0000.0000.0000.2200.2030.5c12.e1a0.bc21.e283.c131.cea1.c66d.6885.7d28.b7b2.fce0.a6fb.c40c.1648.5212.1bc0.c62d.0000.0000.0016.0014.ccf1.af2f.2aab.ee14.bb40.fa38.51ab.2301.de84.3110.a79f.6a00.0000.0000.2200.204a.db4e.2f00.643d.b396.dd12.0d4e.7dc1.7625.f5f2.c11a.40d8.57ac.cc86.2d6b.7dd8.0e04.0048.3045.0221.0098.6746.86a1.3c7d.a2d9.5abe.a08d.27e9.3245.7315.6d79.e5eb.08cd.96d1.e33b.b004.5002.2063.9121.6f4f.d5fb.7b0f.e8c4.3074.fd19.f485.dd47.d7b0.7f73.25c5.a612.1f5b.0a59.1b01.4730.4402.2044.f807.aefa.4148.0a5d.1df2.fc31.2c48.6900.617f.d244.93cf.4197.6428.cb24.9ec2.c202.2007.fd12.29cf.b57d.638b.9c13.7b03.bc79.17d0.e418.b63e.62a3.642f.1c13.354c.c71d.f801.4752.2102.3da0.92f6.980e.58d2.c037.1731.80e9.a465.4760.26ee.50f9.6695.963e.8efe.436f.54eb.2103.0e9f.7b62.3d2c.cc7c.9bd4.4d66.d5ce.21ce.504c.0acf.6385.a132.cec6.d3c3.9fa7.11c1.52ae.3e19.5220]
    ==
  ==
::
++  test-key-derivation
  |^
  ;:  weld
    check-public-key
    check-private-key
    check-revocation-pubkey
    check-revocation-secret
  ==
  ::
  ++  check-public-key
    %+  expect-eq
      !>  public-key
      !>  %+  derive-pubkey:keys:bolt
            basepoint
          per-commitment-point
  ::
  ++  check-private-key
    %+  expect-eq
      !>  private-key
      !>  %^    derive-privkey:keys:bolt
              basepoint
            per-commitment-point
          basepoint-secret
  ::
  ++  check-revocation-pubkey
    %+  expect-eq
      !>  revocation-pubkey
      !>  %+  derive-revocation-pubkey:keys:bolt
            basepoint
          per-commitment-point
  ::
  ++  check-revocation-secret
    %+  expect-eq
      !>  revocation-privkey
      !>  %:  derive-revocation-privkey:keys:bolt
            revocation-basepoint=basepoint
            revocation-basepoint-secret=basepoint-secret
            per-commitment-point=per-commitment-point
            per-commitment-secret=per-commitment-secret
          ==
  ::
  ++  public-key
    ^-  pubkey
    :-  33
    0x2.35f2.dbfa.a89b.57ec.7b05.5afe.2984.9ef7.ddfe.b1ce.fdb9.ebdc.43f5.4949.84db.29e5
  ::
  ++  private-key
    ^-  hexb:bc
    :-  32
    0xcbce.d912.d3b2.1bf1.96a7.6665.1e43.6aff.1923.6262.1ce3.1770.4ea2.f75d.87e7.be0f
  ::
  ++  revocation-pubkey
    ^-  pubkey
    :-  33
    0x2.916e.3266.36d1.9c33.f13e.8c0c.3a03.dd15.7f33.2f3e.99c3.17c1.41dd.865e.b01f.8ff0
  ::
  ++  revocation-privkey
    ^-  hexb:bc
    :-  32
    0xd09f.fff6.2ddb.2297.ab00.0cc8.5bcb.4283.fdeb.6aa0.52af.fbc9.dddc.f33b.6107.8110
  ::
  ++  basepoint-secret
    ^-  hexb:bc
    :-  32
    0x1.0203.0405.0607.0809.0a0b.0c0d.0e0f.1011.1213.1415.1617.1819.1a1b.1c1d.1e1f
  ::
  ++  per-commitment-secret
    ^-  hexb:bc
    :-  32
    0x1f1e.1d1c.1b1a.1918.1716.1514.1312.1110.0f0e.0d0c.0b0a.0908.0706.0504.0302.0100
  ::
  ++  basepoint
    ^-  point
    %-  decompress-point:secp256k1:secp:crypto
    0x3.6d6c.aac2.48af.96f6.afa7.f904.f550.253a.0f3e.f3f5.aa2f.e683.8a95.b216.6914.68e2
  ::
  ++  per-commitment-point
    ^-  point
    %-  decompress-point:secp256k1:secp:crypto
    0x2.5f71.17a7.8150.fe2e.f97d.b7cf.c83b.d57b.2e2c.0d0d.d25e.af46.7a4a.1c2a.45ce.1486
  --
::
++  test-per-commitment-secret-generation
  |^
  ;:  weld
    check-zero-final-node
    check-fs-final-node
    check-fs-alternate-bits-1
    check-fs-alternate-bits-2
    check-last-nontrivial
  ==
  ++  check-zero-final-node
    %+  expect-eq
      !>  [32 0x2a4.0c85.b6f2.8da0.8dfd.be09.26c5.3fab.2de6.d28c.1030.1f8f.7c40.73d5.e42e.3148]
      !>  %+  generate-from-seed:commitment-secret:bolt
            [32 0x0]
          281.474.976.710.655
  ::
  ++  check-fs-final-node
    %+  expect-eq
      !>  [32 0x7cc8.54b5.4e3e.0dcd.b010.d7a3.fee4.64a9.687b.e6e8.db3b.e685.4c47.5621.e007.a5dc]
      !>  %+  generate-from-seed:commitment-secret:bolt
            [32 0xffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff]
          281.474.976.710.655
  ::
  ++  check-fs-alternate-bits-1
    %+  expect-eq
      !>  [32 0x56f4.008f.b007.ca9a.cf0e.15b0.54d5.c9fd.12ee.06ce.a347.914d.dbae.d70d.1c13.a528]
      !>  %+  generate-from-seed:commitment-secret:bolt
            [32 0xffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff]
          0xaaa.aaaa.aaaa
  ::
  ++  check-fs-alternate-bits-2
    %+  expect-eq
      !>  [32 0x9015.daae.b06d.ba4c.cc05.b91b.2f73.bd54.405f.2be9.f217.fbac.d3c5.ac2e.6232.7d31]
      !>  %+  generate-from-seed:commitment-secret:bolt
            [32 0xffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff]
          0x5555.5555.5555
  ::
  ++  check-last-nontrivial
    %+  expect-eq
      !>  [32 0x915c.7594.2a26.bb3a.433a.8ce2.cb04.27c2.9ec6.c177.5cfc.7832.8b57.f6ba.7bfe.aa9c]
      !>  %+  generate-from-seed:commitment-secret:bolt
            [32 0x101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101.0101]
          1
  --
--
