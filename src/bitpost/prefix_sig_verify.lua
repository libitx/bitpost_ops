--[[
Concatenates the given prefix and data string, and then verifies the signature
with the given public key against the concatenated message.

The `prefix` and `data` paramaters must be strings and will be concatenated with
a joining `.` character.

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
        "1TEST"
        "95Wsv5lAHJMuOa-v6SJg6ld_P6EzbemwTGdgVSuM4fw"
        "H5SxczuULA8YKwM/SK20Wp6ucDsIZ9ZhS4S6niDP6pKKToozBf886nNEWTEx/KLVg8EXTj4sYGL9ebZFxe2ddA8="
        0x03e4cc0c595cee4e117203fe9c5cc5f8fcfbfa00a06f8048347c6c08c78f073a49
    # {
    #   signatures: [{
    #     message: "1TEST.95Wsv5lAHJMuOa-v6SJg6ld_P6EzbemwTGdgVSuM4fw",
    #     signature: "H5SxczuULA8YKwM/SK20Wp6ucDsIZ9ZhS4S6niDP6pKKToozBf886nNEWTEx/KLVg8EXTj4sYGL9ebZFxe2ddA8=",
    #     pubkey: "03e4cc0c595cee4e117203fe9c5cc5f8fcfbfa00a06f8048347c6c08c78f073a49",
    #     verified: true,
    #   }]
    # }

@version 0.1.0
@author Bitpost
]]--
return function(state, prefix, data, signature, pubkey)
  state = state or {}

  -- Local helper method to determine if a string is blank
  local function isblank(str)
    return str == nil or str == ''
  end

  assert(
    type(state) == 'table',
    'Invalid state. Must be a table.')
  assert(
    not isblank(prefix),
    'Invalid parameters. Prefix must be present.')
  assert(
    not isblank(data),
    'Invalid parameters. Data must be present.')
  assert(
    not isblank(signature),
    'Invalid parameters. Signature must be present.')
  assert(
    not isblank(pubkey),
    'Invalid parameters. Pubkey must be present.')

  -- Build the signature object
  local sig = {
    message = prefix .. '.' .. data,
    signature = signature,
    pubkey = pubkey,
    verified = false
  }

  -- If the signature is base64 encoded then decode to binary string
  if string.len(signature) == 88 and string.match(signature, '^[a-zA-Z0-9+/=]+$') then
    signature = base.decode64(signature)
  end

  -- If the pubkey is hex encoded then decode to binary string
  if string.len(pubkey) == 66 and string.match(pubkey, '^[a-fA-F0-9]+$') then
    pubkey = base.decode16(pubkey)
  end

  -- Get hash from payload and verify signature
  sig.verified = crypto.bitcoin_message.verify(signature, sig.message, pubkey, {encoding = 'binary'})

  -- Add signature to state
  state.signatures = state.signatures or {}
  table.insert(state.signatures, sig)

  return state
end
