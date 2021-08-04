/+  bc=bitcoin
|%
++  sigma
  ^-  (list @ux)
  ~[0x6170.7865 0x3320.646e 0x7962.2d32 0x6b20.6574]
++  num-rounds  20
--
::  key: 256 bit key, little endian
::  nonce: 96 bit nonce, little endian
::  counter: 32 bit counter, little endian
::
::
|_  [key=hexb:bc nonce=hexb:bc counter=hexb:bc]
::  +apply: xor stream with data
++  apply
  |=  [data=hexb:bc]
  ^-  hexb:bc
  ~|  "Invalid parameters"
  ?>  ?&  =(32 wid.key)
          =(12 wid.nonce)
          =(4 wid.counter)
      ==
    1^0x0
::
++  internal
  =,  byt:bc
  |%
  ++  params
    ^-  (list @ux)
    ;:  weld
      sigma
      (split-4 key 8)
      (split-4 counter 1)
      (split-4 nonce 3)
    ==
  ::  +split: split bytestream into b 4-byte parts
  ::  convert a from little endian to big endian
  ::
  ++  split-4
    |=  [a=hexb:bc b=@]
    ^-  (list @ux)
    ~|  "bytestream of length {<wid.a>} too short for {<b>} 4-byte parts"
    ?>  (gte wid.a (mul 4 b))
    =|  res=(list @ux)
    |-
    ?:  =(0 b)  res
    %_  $
        res  (snoc res dat:(flip (take 4 a)))
        b    (dec b)
        a    (drop 4 a)
    ==
  ::
  ++  chacha
    |=  [rounds=@ud]
    ^-  (list @ux)
    =/  params=(list @ux)  params
    =/  mix=(list @ux)     params
    =.  mix
      |-
      ?:  (lte rounds 0)  mix
      =.  mix  (quarter-round mix 0 4 8 12)
      =.  mix  (quarter-round mix 1 5 9 13)
      =.  mix  (quarter-round mix 2 6 10 14)
      =.  mix  (quarter-round mix 3 7 11 15)
      =.  mix  (quarter-round mix 0 5 10 15)
      =.  mix  (quarter-round mix 1 6 11 12)
      =.  mix  (quarter-round mix 2 7 8 13)
      =.  mix  (quarter-round mix 3 4 9 14)
      $(rounds (sub rounds 2))
    =|  keystream=(list @ux)
    =|  i=@ud
    |-
    ?:  =(i 16)  keystream
    =/  ith=@ux  (add (snag i params) (snag i mix))
    =.  keystream
      %+  weld  keystream
      %+  turn  (gulf 0 3)
        |=  shift=@
        ^-  @ux
        %+  rsh  [3 shift]
        (dis ith 0xff)
    $(i +(i))
  ::
  ++  quarter-round
    |=  [output=(list @ux) a=@ b=@ c=@ d=@]
    ^-  (list @ux)
    |^
    =.  output  (mix-outputs output d a b 16)
    =.  output  (mix-outputs output b c d 12)
    =.  output  (mix-outputs output d a b 8)
    (mix-outputs output b c d 7)
    ::
    ++  mix-outputs
      |=  [o=(list @ux) i1=@ i2=@ i3=@ shift=@]
      ^-  (list @ux)
      =.  o
        %^  snap  o  i2
        %+  end  [0 32]
        (add (snag i2 o) (snag i3 o))
      %^  snap  o  i1
     (rotl (mix (snag i1 o) (snag i2 o)) shift)
    ::  Cyclic left rotation
    ::
    ++  rotl
      |=  [data=@ shift=@]
      ^-  @
      %+  con
        (end [0 32] (lsh [0 shift] data))      ::  drop left bits beyond 32 bits
      (rsh [0 (sub 32 shift)] (end [0 32] data))
    --
  --
--
