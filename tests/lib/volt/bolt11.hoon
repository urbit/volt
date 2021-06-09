/-  btc=bitcoin
/+  *test, bolt11=volt-bolt11
=,  btc
|%
::
++  rhash
  :*  wid=32
      dat=0x1.0203.0405.0607.0809.0001.0203.0405.0607.0809.0001.0203.0405.0607.0809.0102
  ==
++  privkey
  :*  wid=32
      dat=0xe126.f68f.7eaf.cc8b.74f5.4d26.9fe2.06be.7150.00f9.4dac.067d.1c04.a8ca.3b2d.b734
  ==
++  pubkey
  :*  wid=33
      dat=0x3.e715.6ae3.3b0a.208d.0744.1991.6317.7e90.9e80.176e.55d9.7a2f.221e.de0f.934d.d9ad
  ==
++  time  ~2017.6.1..10.57.38
::
+$  bolt11-test-vector  [encoded=@t decoded=(unit invoice:bolt11)]
::
++  bolt11-test-vectors
  :~
    :-  'lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w'
    %-  some
    %-  invoice:bolt11
    :*  network=%main
        timestamp=time
        payment-hash=rhash
        payment-secret=~
        signature=[v=0 r=0x38ec.6891.345e.2041.45be.8a3a.99de.38e9.8a39.d6a5.6943.4e18.45c8.af72.05af.cfcc s=0x7f42.5fcd.1463.e93c.3288.1ead.0d6e.356d.467e.c8c0.2553.f9aa.b15e.5738.b11f.127f]
        pubkey=pubkey
        expiry=~s3600
        min-final-cltv-expiry=18
        amount=~
        description=(some 'Please consider supporting this project')
        description-hash=~
        unknown-tags=*(map @tD hexb)
        fallback-address=~
        route=~
        feature-bits=0^0b0
    ==
    ::  please send $3 for a cup of coffee to the same peer, within one minute
    :-  'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp'
    %-  some
    %-  invoice:bolt11
    :*  network=%main
        timestamp=time
        payment-hash=rhash
        payment-secret=~
        signature=[v=1 r=0xe896.39ba.6814.e366.89d4.b91b.f125.f103.51b5.5da0.57b0.0647.a8da.baeb.8a90.c95f s=0x160f.9d5a.6e0f.79d1.fc2b.9642.38b9.44e2.fa4a.a677.c6f0.20d4.6647.2ab8.42bd.750e]
        pubkey=pubkey
        expiry=~s60
        min-final-cltv-expiry=18
        amount=(some [2.500 (some %u)])
        description=(some '1 cup coffee')
        description-hash=~
        unknown-tags=*(map @tD hexb)
        fallback-address=~
        route=~
        feature-bits=0^0b0
    ==
    ::  please send 0.0025 BTC for a cup of nonsense to the same peer, within one minute
    :-  'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny'
    %-  some
    %-  invoice:bolt11
    :*  network=%main
        timestamp=time
        payment-hash=rhash
        payment-secret=~
        signature=[v=0 r=0x259f.0451.1e7e.f2aa.77f6.ff04.d51b.4ae9.2095.0484.3e5a.b967.2ce3.2a15.3681.f687 s=0x515b.73ce.57ee.309d.b588.a10e.b8e4.1b5a.2d2b.c171.44dd.f398.033f.aa49.ffe9.5ae6]
        pubkey=pubkey
        expiry=~s60
        min-final-cltv-expiry=18
        amount=(some [2.500 (some %u)])
        description=(some 'ナンセンス 1杯')
        description-hash=~
        unknown-tags=*(map @tD hexb)
        fallback-address=~
        route=~
        feature-bits=0^0b0
    ==
    ::  now send $24 for an entire list of things (hashed)
    :-  'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7'
    %-  some
    %-  invoice:bolt11
    :*  network=%main
        timestamp=time
        payment-hash=rhash
        payment-secret=~
        signature=[v=0 r=0xc634.86e8.1f8c.878a.105b.c9d9.59af.1973.854c.4dc5.52c4.f0e0.e0c7.3896.03d6.bdc6 s=0x7707.bf6b.e992.a8ce.7bf5.0016.bb41.d8a9.b535.8652.c496.0445.a170.d049.ced4.558c]
        pubkey=pubkey
        expiry=~m60
        min-final-cltv-expiry=18
        amount=(some [20 (some %m)])
        description=~
        description-hash=(some [wid=32 dat=0x3925.b6f6.7e2c.3400.36ed.1209.3dd4.4e03.68df.1b6e.a26c.53db.e481.1f58.fd5d.b8c1])
        unknown-tags=*(map @tD hexb)
        fallback-address=~
        route=~
        feature-bits=0^0b0
    ==
    ::  the same, on testnet, with fallback address mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP
    :-  'lntb20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98kmzzhznpurw9sgl2v0nklu2g4d0keph5t7tj9tcqd8rexnd07ux4uv2cjvcqwaxgj7v4uwn5wmypjd5n69z2xm3xgksg28nwht7f6zspwp3f9t'
    %-  some
    %-  invoice:bolt11
    :*  network=%testnet
        timestamp=time
        payment-hash=rhash
        payment-secret=~
        signature=[v=1 r=0xb6c4.2b8a.61e0.dc58.23ea.63e7.6ff1.48ab.5f6c.86f4.5f97.22af.0069.c793.4daf.f70d s=0x5e31.5893.3007.74c8.9799.5e3a.7476.c819.3693.d144.a36e.2645.a085.1e6e.bafc.9d0a]
        pubkey=pubkey
        expiry=~m60
        min-final-cltv-expiry=18
        amount=(some [20 (some %m)])
        description=~
        description-hash=(some [wid=32 dat=0x3925.b6f6.7e2c.3400.36ed.1209.3dd4.4e03.68df.1b6e.a26c.53db.e481.1f58.fd5d.b8c1])
        unknown-tags=*(map @tD hexb)
        fallback-address=(some [%base58 0cmk2QpYatsKicvFVuTAQLBryyccRXMUaGHP])
        route=~
        feature-bits=0^0b0
    ==
    ::  on mainnet, with fallback address 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T with extra routing info
    :-  'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj'
    =/  r=(list route:bolt11)
    :~  :*  pubkey=[wid=33 dat=0x2.9e03.a901.b855.34ff.1e92.c43c.7443.1f7c.e720.4606.0fcf.7a95.c37e.148f.78c7.7255]
            short-channel-id=`@ud`0x102.0304.0506.0708
            feebase=1
            feerate=20
            cltv-expiry-delta=3
        ==
        ::
        :*  pubkey=[wid=33 dat=0x3.9e03.a901.b855.34ff.1e92.c43c.7443.1f7c.e720.4606.0fcf.7a95.c37e.148f.78c7.7255]
            short-channel-id=`@ud`0x304.0506.0708.090a
            feebase=2
            feerate=30
            cltv-expiry-delta=4
        ==
    ==
    %-  some
    %-  invoice:bolt11
    :*  network=%main
        timestamp=time
        payment-hash=rhash
        payment-secret=~
        signature=[v=0 r=0x9167.5cb3.fad8.e9d9.1534.3883.a492.42e0.7447.4e26.d42c.7ed9.1465.5689.a807.4553 s=0x733e.8e4e.a5ce.9b85.f69e.40d7.55a5.5014.536b.1232.3f8b.2206.00c9.4ef2.b9c5.1428]
        pubkey=pubkey
        expiry=~m60
        min-final-cltv-expiry=18
        amount=(some [20 (some %m)])
        description=~
        description-hash=(some [wid=32 dat=0x3925.b6f6.7e2c.3400.36ed.1209.3dd4.4e03.68df.1b6e.a26c.53db.e481.1f58.fd5d.b8c1])
        unknown-tags=*(map @tD hexb)
        fallback-address=(some [%base58 0c1RustyRX2oai4EYYDpQGWvEL62BBGqN9T])
        route=r
        feature-bits=0^0b0
    ==
    ::  on mainnet, with fallback (P2SH) address 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
    :-  'lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9kmrgvr7xlaqm47apw3d48zm203kzcq357a4ls9al2ea73r8jcceyjtya6fu5wzzpe50zrge6ulk4nvjcpxlekvmxl6qcs9j3tz0469gq5g658y'
    %-  some
    %-  invoice:bolt11
    :*  network=%main
        timestamp=time
        payment-hash=rhash
        payment-secret=~
        signature=[v=0 r=0xb6c6.860f.c6ff.41ba.fba1.745b.538b.6a7c.6c2c.0234.f76b.f817.bf56.7be8.8cf2.c632 s=0x492c.9dd2.7947.0841.cd1e.21a3.3ae7.ed59.b258.09bf.9b33.66fe.8188.1651.589f.5d15]
        pubkey=pubkey
        expiry=~m60
        min-final-cltv-expiry=18
        amount=(some [20 (some %m)])
        description=~
        description-hash=(some [wid=32 dat=0x3925.b6f6.7e2c.3400.36ed.1209.3dd4.4e03.68df.1b6e.a26c.53db.e481.1f58.fd5d.b8c1])
        unknown-tags=*(map @tD hexb)
        fallback-address=(some [%base58 0c3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX])
        route=~
        feature-bits=0^0b0
    ==
    ::  on mainnet, with fallback (P2WPKH) address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
    :-  'lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8'
    %-  some
    %-  invoice:bolt11
    :*  network=%main
        timestamp=time
        payment-hash=rhash
        payment-secret=~
        signature=[v=0 r=0xc858.3b8f.6585.3d7c.c90f.0eb4.ae0e.92a6.06f8.9caf.4f7d.6504.8142.d7bb.d4e5.f362 s=0x3ef4.07a7.5458.e4b2.0f00.efbc.734f.1c2e.efc4.19f3.a2be.6d51.0380.16ff.b35c.d613]
        pubkey=pubkey
        expiry=~m60
        min-final-cltv-expiry=18
        amount=(some [20 (some %m)])
        description=~
        description-hash=(some [wid=32 dat=0x3925.b6f6.7e2c.3400.36ed.1209.3dd4.4e03.68df.1b6e.a26c.53db.e481.1f58.fd5d.b8c1])
        unknown-tags=*(map @tD hexb)
        fallback-address=(some [%bech32 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'])
        route=~
        feature-bits=0^0b0
    ==
  ==
::
++  test-all-vectors
  ^-  tang
  |^
  ;:  weld
    %+  category  "invoice decoding"
    (zing (turn bolt11-test-vectors check-decode))
    ::
    %+  category  "invoice encoding"
    (zing (turn bolt11-test-vectors check-encode))
  ==
  ++  check-decode
    |=  v=bolt11-test-vector
    %+  expect-eq
      !>(+.v)
      !>((de:bolt11 -.v))
  ::
  ++  check-encode
    |=  v=bolt11-test-vector
    %+  expect-eq
      !>(0)
      !>(0)
  --
::
--
