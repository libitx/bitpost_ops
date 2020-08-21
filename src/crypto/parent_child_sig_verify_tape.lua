--[[
Verifies both a parent and child signature, using the given public keys. Using
two signatures allows Metanet-like tx graphs to be created, without need to
sign inputs and with more flexible ownership properties.

The message the parent signature is verified against is all of the script data
from the specified output index. The data is hashed using the SHA-256 algorithm
and then signed.

The child signature is verified against the a subscripte made up from the
`tape_idx`, `parent_sig` and `parent_pubkey` parameters. It is hashed using the
SHA-256 algorithm and then signed

The `tape_idx` parameter is the output index of the tape containg the data to
verify the parent signature against. The value can either be utf8 encoded or an
unsigned integer.

he `parent_sig` and `child_sig` paramaters can be in either of the following
formats:

  * Raw 65 byte binary signature
  * Base64 encoded string

The `parent_pubkey` and `child_pubkey` parameters can be in any of the following
formats:

  * Raw 33 byte binary public key
  * Hex encoded string
  * A Bitcoin address string

## Examples

    OP_FALSE OP_RETURN
      $REF
        "1"
        "H9o/19warnGfa1dfblvYLQFKCQa+KLnegyuCTAtR5wwuM/PKqCOvrWUgnVOd4QOq48AjAQ1ej+P6aPf6kHe8I78="
        "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
        "IPIeRTkp48ykrrXmW7OBry8/uA0o8mLQF4Kvu7urhV1CPz67urWhK1epgqEL8Z1uZV4OIxYuzs5JAli1YS0+Is4="
        "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"
    # {
    #   signatures: {
    #     parent: {
    #       hash: "49659874a1dd58cb2e244d5686f8f2723fbe636475ce1649bf93cc3d1cc56b9f",
    #       signature: "H9o/19warnGfa1dfblvYLQFKCQa+KLnegyuCTAtR5wwuM/PKqCOvrWUgnVOd4QOq48AjAQ1ej+P6aPf6kHe8I78=",
    #       pubkey: "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF",
    #       verified: true,
    #     },
    #     child: {
    #       hash: "20c231fd924816f4485216ea26e51e876033256a91e3dccc371dda4d00a7d078",
    #       signature: "IPIeRTkp48ykrrXmW7OBry8/uA0o8mLQF4Kvu7urhV1CPz67urWhK1epgqEL8Z1uZV4OIxYuzs5JAli1YS0+Is4=",
    #       pubkey: "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd",
    #       verified: true,
    #     },
    #   }
    # }

@version 0.1.1
@author Bitpost
]]--
return function(state, tape_idx, parent_sig, parent_pubkey, child_sig, child_pubkey)
  state = state or {}

  -- Local helper method to determine if a string is blank
  local function isblank(str)
    return str == nil or str == ''
  end

  assert(
    type(state) == 'table',
    'Invalid state. Must receive a table.')
  assert(
    not isblank(tape_idx),
    'Invalid tape index. Must receive tape index.')
  assert(
    not isblank(parent_sig) and not isblank(parent_pubkey),
    'Invalid parameters. Must receive parent signature and addr.')
  assert(
    not isblank(child_sig) and not isblank(child_pubkey),
    'Invalid parameters. Must receive self signature and addr.')

  -- Build the signature object
  local sig = {
    parent = {
      signature = parent_sig,
      pubkey = parent_pubkey,
      verified = false
    },
    child = {
      signature = child_sig,
      pubkey = child_pubkey,
      verified = false
    }
  }

  -- Convert tape index to integer
  if string.match(tape_idx, '^[0-9]+$') then
    tape_idx = math.floor(tonumber(tape_idx))
  else
    tape_idx = table.unpack(string.unpack('I1', tape_idx))
  end

  -- If the signatures are base64 encoded then decode to binary string
  if string.len(parent_sig) == 88 and string.match(parent_sig, '^[a-zA-Z0-9+/=]+$') then
    parent_sig = base.decode64(parent_sig)
  end
  if string.len(child_sig) == 88 and string.match(child_sig, '^[a-zA-Z0-9+/=]+$') then
    child_sig = base.decode64(child_sig)
  end

  -- If the pubkeys are hex encoded then decode to binary string
  if string.len(parent_pubkey) == 66 and string.match(parent_pubkey, '^[a-fA-F0-9]+$') then
    parent_pubkey = base.decode16(parent_pubkey)
  end
  if string.len(child_pubkey) == 66 and string.match(child_pubkey, '^[a-fA-F0-9]+$') then
    child_pubkey = base.decode16(child_pubkey)
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
    local message1 = ''
    for idx = 1, #tape do
      local data = tape[idx]
      if data.op == nil then
        message1 = message1 .. pushint(string.len(data.b)) .. data.b
      else
        message1 = message1 .. data.b
      end
    end
    local hash1 = crypto.hash.sha256(message1)
    sig.parent.hash = base.encode16(hash1)
    sig.parent.verified = crypto.bitcoin_message.verify(parent_sig, hash1, parent_pubkey, {encoding = 'binary'})

    -- Build child sig from parent signature params
    local parts = {tape_idx, parent_sig, parent_pubkey}
    local message2 = ''
    for idx = 1, #parts do
      local data = parts[idx]
      message2 = message2 .. pushint(string.len(data)) .. data
    end
    local hash2 = crypto.hash.sha256(message2)
    sig.child.hash = base.encode16(hash2)
    sig.child.verified = crypto.bitcoin_message.verify(child_sig, hash2, child_pubkey, {encoding = 'binary'})
  end

  -- Add signature to state
  state.signatures = state.signatures or {}
  state.signatures.parent = sig.parent
  state.signatures.child = sig.child

  return state
end
