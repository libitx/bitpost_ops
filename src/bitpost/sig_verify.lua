--[[
Verifies a timestamped signature with the given public key. The message the
signature is verified against is all of the script data from the specified
output index, hashed using the SHA-256 algorithm, and optionally appended with a
unix timestamp.

    sign(sha256(output)++timestamp)

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

The `timestamp` is a linux timestamp and should be given as a utf8 encoded
string. The timestamp is optional.

## Examples

    OP_FALSE OP_RETURN
      $REF
        "1"
        "IPOJjDEQC2s44zbZCEPpjjFUA6w8DmMbpqpijSn0k44xQco4AU0RBp2aBZ3H/KgV3+u0l3e6YFeVNOidT0z0nbY="
        "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
        "1599495325"
    # {
    #   signatures: [{
    #     hash: "677ae98e74ebe6d68f93440bf2ebebdf35d7645a28c44220c88cab430b3b5734",
    #     signature: "IPOJjDEQC2s44zbZCEPpjjFUA6w8DmMbpqpijSn0k44xQco4AU0RBp2aBZ3H/KgV3+u0l3e6YFeVNOidT0z0nbY=",
    #     pubkey: "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF",
    #     timestamp: 1599495325,
    #     verified: true,
    #   }]
    # }

@version 0.2.2
@author Bitpost
]]--
return function(state, tape_idx, signature, pubkey, timestamp)
  state = state or {}
  timestamp = timestamp or ''

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
    elseif  int < 0x100       then return string.pack('BI1', 76, int)
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
    sig.verified = crypto.bitcoin_message.verify(signature, hash..timestamp, pubkey, {encoding = 'binary'})
  end

  -- Add timestamp to sig table
  if string.len(timestamp) > 0 then
    timestamp = math.floor(tonumber(timestamp))
  end
  sig.timestamp = timestamp

  -- Add signature to state
  state.signatures = state.signatures or {}
  table.insert(state.signatures, sig)

  return state
end
