::  script.hoon
::
/+  bc=bitcoin
|%
::
+$  script  (list op)
::
+$  op
  $@  $?  %op-0
          %op-1negate
      ::
          %op-1
          %op-2
          %op-3
          %op-4
          %op-5
          %op-6
          %op-7
          %op-8
          %op-9
          %op-10
          %op-11
          %op-12
          %op-13
          %op-14
          %op-15
          %op-16
      ::
          %op-nop
          %op-if
          %op-notif
          %op-else
          %op-endif
          %op-verify
          %op-return
      ::
          %op-toaltstack
          %op-fromaltstack
          %op-ifdup
          %op-depth
          %op-drop
          %op-dup
          %op-nip
          %op-over
          %op-pick
          %op-roll
          %op-rot
          %op-swap
          %op-tuck
          %op-2drop
          %op-2dup
          %op-3dup
          %op-2over
          %op-2rot
          %op-2swap
      ::
          %op-cat
          %op-substr
          %op-left
          %op-right
          %op-size
      ::
          %op-invert
          %op-and
          %op-or
          %op-xor
          %op-equal
          %op-equalverify
      ::
          %op-1add
          %op-1sub
          %op-2mul
          %op-2div
          %op-negate
          %op-abs
          %op-not
          %op-0notequal
          %op-add
          %op-sub
          %op-mul
          %op-div
          %op-mod
          %op-lshift
          %op-rshift
          %op-booland
          %op-boolor
          %op-numequal
          %op-numequalverify
          %op-numnotequal
          %op-lessthan
          %op-greaterthan
          %op-lessthanorequal
          %op-greaterthanorequal
          %op-min
          %op-max
          %op-within
      ::
          %op-ripemd160
          %op-sha1
          %op-sha256
          %op-hash160
          %op-hash256
          %op-codeseparator
          %op-checksig
          %op-checksigverify
          %op-checkmultisig
          %op-checkmultisigverify
      ::
          %op-checklocktimeverify
          %op-checksequenceverify
      ::
          %op-pubkeyhash
          %op-pubkey
          %op-invalidopcode
      ::
          %op-reserved
          %op-ver
          %op-verif
          %op-vernotif
          %op-reserved1
          %op-reserved2
      ::
          %op-nop1
          %op-nop4
          %op-nop5
          %op-nop6
          %op-nop7
          %op-nop8
          %op-nop9
          %op-nop10
      ==
  $%  [%op-pushdata =byts]
  ==
::
++  en
  |=  =script
  |^  ^-  byts
  %-  cat:byt:bc
  %+  turn  script  encode-op
  ::
  ++  encode-op
    |=  =op
    ^-  byts
    ?:  ?=(^ op)
      ?>  ?=([%op-pushdata *] op)
      (encode-pushdata +.op)
    ::
    ?-  op
      %op-0                    [1 0x0]
      %op-1negate              [1 0x4f]
      %op-reserved             [1 0x50]
      %op-1                    [1 0x51]
      %op-2                    [1 0x52]
      %op-3                    [1 0x53]
      %op-4                    [1 0x54]
      %op-5                    [1 0x55]
      %op-6                    [1 0x56]
      %op-7                    [1 0x57]
      %op-8                    [1 0x58]
      %op-9                    [1 0x59]
      %op-10                   [1 0x5a]
      %op-11                   [1 0x5b]
      %op-12                   [1 0x5c]
      %op-13                   [1 0x5d]
      %op-14                   [1 0x5e]
      %op-15                   [1 0x5f]
      %op-16                   [1 0x60]
    ::
      %op-nop                  [1 0x61]
      %op-ver                  [1 0x62]
      %op-if                   [1 0x63]
      %op-notif                [1 0x64]
      %op-verif                [1 0x65]
      %op-vernotif             [1 0x66]
      %op-else                 [1 0x67]
      %op-endif                [1 0x68]
      %op-verify               [1 0x69]
      %op-return               [1 0x6a]
      %op-toaltstack           [1 0x6b]
      %op-fromaltstack         [1 0x6c]
      %op-2drop                [1 0x6d]
      %op-2dup                 [1 0x6e]
      %op-3dup                 [1 0x6f]
      %op-2over                [1 0x70]
      %op-2rot                 [1 0x71]
      %op-2swap                [1 0x72]
      %op-ifdup                [1 0x73]
      %op-depth                [1 0x74]
      %op-drop                 [1 0x75]
      %op-dup                  [1 0x76]
      %op-nip                  [1 0x77]
      %op-over                 [1 0x78]
      %op-pick                 [1 0x79]
      %op-roll                 [1 0x7a]
      %op-rot                  [1 0x7b]
      %op-swap                 [1 0x7c]
      %op-tuck                 [1 0x7d]
      ::
      %op-cat                  [1 0x7e]
      %op-substr               [1 0x7f]
      %op-left                 [1 0x80]
      %op-right                [1 0x81]
      %op-size                 [1 0x82]
      %op-invert               [1 0x83]
      %op-and                  [1 0x84]
      %op-or                   [1 0x85]
      %op-xor                  [1 0x86]
      %op-equal                [1 0x87]
      %op-equalverify          [1 0x88]
      %op-reserved1            [1 0x89]
      %op-reserved2            [1 0x8a]
      ::
      %op-1add                 [1 0x8b]
      %op-1sub                 [1 0x8c]
      %op-2mul                 [1 0x8d]
      %op-2div                 [1 0x8e]
      %op-negate               [1 0x8f]
      %op-abs                  [1 0x90]
      %op-not                  [1 0x91]
      %op-0notequal            [1 0x92]
      %op-add                  [1 0x93]
      %op-sub                  [1 0x94]
      %op-mul                  [1 0x95]
      %op-div                  [1 0x96]
      %op-mod                  [1 0x97]
      %op-lshift               [1 0x98]
      %op-rshift               [1 0x99]
      %op-booland              [1 0x9a]
      %op-boolor               [1 0x9b]
      %op-numequal             [1 0x9c]
      %op-numequalverify       [1 0x9d]
      %op-numnotequal          [1 0x9e]
      %op-lessthan             [1 0x9f]
      %op-greaterthan          [1 0xa0]
      %op-lessthanorequal      [1 0xa1]
      %op-greaterthanorequal   [1 0xa2]
      %op-min                  [1 0xa3]
      %op-max                  [1 0xa4]
      %op-within               [1 0xa5]
      ::
      %op-ripemd160            [1 0xa6]
      %op-sha1                 [1 0xa7]
      %op-sha256               [1 0xa8]
      %op-hash160              [1 0xa9]
      %op-hash256              [1 0xaa]
      %op-codeseparator        [1 0xab]
      %op-checksig             [1 0xac]
      %op-checksigverify       [1 0xad]
      %op-checkmultisig        [1 0xae]
      %op-checkmultisigverify  [1 0xaf]
      ::
      %op-checklocktimeverify  [1 0xb1]
      %op-checksequenceverify  [1 0xb2]
      ::
      %op-pubkeyhash           [1 0xfd]
      %op-pubkey               [1 0xfe]
      %op-invalidopcode        [1 0xff]
      ::
      %op-nop1                 [1 0xb0]
      %op-nop4                 [1 0xb3]
      %op-nop5                 [1 0xb4]
      %op-nop6                 [1 0xb5]
      %op-nop7                 [1 0xb6]
      %op-nop8                 [1 0xb7]
      %op-nop9                 [1 0xb8]
      %op-nop10                [1 0xb9]
    ==
  ::
  ++  encode-pushdata
    |=  a=byts
    ^-  byts
    =/  n=@  wid.a
    %-  cat:byt:bc
    ?:  (lte n 0x4b)
      ~[[1 n] a]
    ::
    ?:  (lte n 0xff)
      ~[[1 0x4c] [1 n] a]
    ::
    ?:  (lte n 0xffff)
      ~[[1 0x4d] [2 n] a]
    ::
    ?:  (lte n 0xffff.ffff)
      ~[[1 0x4c] [4 n] a]
    ::
    ~|("OP_PUSHDATA payload too big" !!)
  --
--
