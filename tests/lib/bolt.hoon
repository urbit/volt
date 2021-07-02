::
/-  *bolt
/+  *test, bolt, bc=bitcoin
|%
++  test-obscure-commitment-number
  =,  bolt-tx:bolt
  =,  secp:crypto
  =|  lar=larva-chan:bolt
  =|  oc=open-channel:msg:bolt
  =|  ac=accept-channel:msg:bolt
  =.  payment.basepoints.oc
    %-  decompress-point:secp256k1
    0x3.4f35.5bdc.b7cc.0af7.28ef.3cce.b961.5d90.684b.b5b2.ca5f.859a.b0f0.b704.0758.71aa
  =.  payment.basepoints.ac
    %-  decompress-point:secp256k1
    0x3.2c0b.7cf9.5324.a07d.0539.8b24.0174.dc0c.2be4.44d9.6b15.9aa6.c7f7.b1e6.6868.0991
  =.  oc.lar  (some oc)
  =.  ac.lar  (some ac)
  =/  cn=@ud  42
  %+  expect-eq
    !>(`@ux`(mix 0x2bb0.3852.1914 cn))
    !>(`@ux`(obscured-commitment-number lar cn))
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
    !>  %-  en:script
        %+  output-script:funding
          local-funding-pubkey
        remote-funding-pubkey
  ::
  ++  check-funding-tx
    %+  expect-eq
      !>  funding-tx
      !>  %-  segwit-encode:bitcoin-txu
          %:  tx:funding
            local-funding-pubkey
            remote-funding-pubkey
            10.000.000
            funding-inputs
            funding-change
            ~
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
--
