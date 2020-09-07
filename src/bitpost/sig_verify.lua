--[[
Verifies the given signature using the public key. The message signature is
verified against is all of the script data from the specified output index. The
data is hashed using the SHA-256 algorithm and then signed.

The `tape_idx` parameter is the output index of the tape containg the data to
verify the parent signature against. The value can either be utf8 encoded or an
unsigned integer.

The `signature` paramater can be in any of the following formats:

  * Raw 65 byte binary signature
  * Base64 encoded string

The `pubkey` parameter can be in any of the following formats:

  * Raw 33 byte binary public key
  * Hex encoded string
  * A Bitcoin address string

## Examples

    OP_FALSE OP_RETURN
      $REF
        "1"
        "H9o/19warnGfa1dfblvYLQFKCQa+KLnegyuCTAtR5wwuM/PKqCOvrWUgnVOd4QOq48AjAQ1ej+P6aPf6kHe8I78="
        "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
    # {
    #   signatures: [{
    #     hash: "49659874a1dd58cb2e244d5686f8f2723fbe636475ce1649bf93cc3d1cc56b9f",
    #     signature: "H9o/19warnGfa1dfblvYLQFKCQa+KLnegyuCTAtR5wwuM/PKqCOvrWUgnVOd4QOq48AjAQ1ej+P6aPf6kHe8I78=",
    #     pubkey: "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF",
    #     verified: true,
    #   }]
    # }

@version 0.1.0
@author Bitpost
]]--
return function(state, tape_idx, signature, pubkey)
  state = state or {}

  -- Local helper method to determine if a string is blank
  local function isblank(str)
    return str == nil or str == ''
  end

  assert(
    type(state) == 'table',
    'Invalid state. Must be a table.')
  assert(
    not isblank(tape_idx),
    'Invalid parameters. Tape index must be present.')
  assert(
    not isblank(signature),
    'Invalid parameters. Signature must be present.')
  assert(
    not isblank(pubkey),
    'Invalid parameters. Pubkey must be present.')

  -- Build the signature object
  local sig = {
    signature = signature,
    pubkey = pubkey,
    verified = false
  }

  -- Convert tape index to integer
  if string.match(tape_idx, '^[0-9]+$') then
    tape_idx = math.floor(tonumber(tape_idx))
  else
    tape_idx = table.unpack(string.unpack('I1', tape_idx))
  end

  -- If the signature is base64 encoded then decode to binary string
  if string.len(signature) == 88 and string.match(signature, '^[a-zA-Z0-9+/=]+$') then
    signature = base.decode64(signature)
  end

  -- If the pubkey is hex encoded then decode to binary string
  if string.len(pubkey) == 66 and string.match(pubkey, '^[a-fA-F0-9]+$') then
    pubkey = base.decode16(pubkey)
  end

  -- Local helper method for encoding an integer into a variable length binary
  local function pushint(int)
    if      int < 76          then return string.pack('B', int)
    elseif  int < 0x100       then return string.pack('B', 76, int)
    elseif  int < 0x10000     then return string.pack('B<I2', 77, int)
    elseif  int < 0x100000000 then return string.pack('B<I4', 78, int)
    else                           error('Push data too large')
    end
  end

  -- Get tape data, then iterate over tape data to build message for verification
  local tape = ctx.get_tape(tape_idx)
  if tape ~= nil then
    local message = ''
    for idx = 1, #tape do
      local data = tape[idx]
      if data.op == nil then
        message = message .. pushint(string.len(data.b)) .. data.b
      else
        message = message .. data.b
      end
    end
    local hash = crypto.hash.sha256(message)
    sig.hash = base.encode16(hash)
    sig.verified = crypto.bitcoin_message.verify(signature, hash, pubkey, {encoding = 'binary'})
  end

  -- Add signature to state
  state.signatures = state.signatures or {}
  table.insert(state.signatures, sig)

  return state
end
