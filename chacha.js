const quarterround = (output, a, b, c, d) => {
  output[d] = rotl(output[d] ^ (output[a] += output[b]), 16)
  output[b] = rotl(output[b] ^ (output[c] += output[d]), 12)
  output[d] = rotl(output[d] ^ (output[a] += output[b]), 8)
  output[b] = rotl(output[b] ^ (output[c] += output[d]), 7)

  // JavaScript hack to make UINT32 :) //
  output[a] >>>= 0
  output[b] >>>= 0
  output[c] >>>= 0
  output[d] >>>= 0
};

const rotl = (data, shift) => {
  return ((data << shift) | (data >>> (32 - shift)))
};

exports.qr = quarterround;
