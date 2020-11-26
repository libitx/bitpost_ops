--[[
Verifies a DER-encoded ECDSA signature with the given public key against the
given message.

The `message` parameter can be any binary string and will be hashed using the
`SHA-256` algorithm.

The `signature` paramater can be in any of the following formats:

  * Raw 70-72 byte DER-encoded signature
  * Base64 encoded string

The `pubkey` parameter can be in any of the following formats:

  * Raw 33 byte binary public key
  * Hex encoded string

## Examples

    OP_FALSE OP_RETURN
      $REF
        "95Wsv5lAHJMuOa-v6SJg6ld_P6EzbemwTGdgVSuM4fw"
        "MEUCIQD2CFpfjhF65pOZEMSQ7KAIBWpG/CXMzhi2Q72dFybj3AIgbHDmUoAv1zS74PVJgiPSyjanEqp+TdxNcEeSDfvfvEg="
        0x02f8fb290f533f740c95c62c5f99f222642ed739561ae691147caff630677dfa0e
    # {
    #   signatures: [{
    #     hash: "64e7189c2dbb60e4f28af0431dab4a90bacb3472ed77befaf053f644a349d830",
    #     signature: "MEUCIQD2CFpfjhF65pOZEMSQ7KAIBWpG/CXMzhi2Q72dFybj3AIgbHDmUoAv1zS74PVJgiPSyjanEqp+TdxNcEeSDfvfvEg=",
    #     pubkey: "02f8fb290f533f740c95c62c5f99f222642ed739561ae691147caff630677dfa0e",
    #     verified: true,
    #   }]
    # }

@version 0.1.0
@author Bitpost
]]--
return function(state, message, signature, pubkey)
  state = state or {}

  -- Local helper method to determine if a string is blank
  local function isblank(str)
    return str == nil or str == ''
  end

  assert(
    type(state) == 'table',
    'Invalid state. Must be a table.')
  assert(
    not isblank(message),
    'Invalid parameters. Message must be present.')
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

  -- If the signature is base64 encoded then decode to binary string
  if string.len(signature) > 72 and string.match(signature, '^[a-zA-Z0-9+/=]+$') then
    signature = base.decode64(signature)
  end

  -- If the pubkey is hex encoded then decode to binary string
  if string.len(pubkey) == 66 and string.match(pubkey, '^[a-fA-F0-9]+$') then
    pubkey = base.decode16(pubkey)
  end

  -- Get hash from message and verify signature
  local hash = crypto.hash.sha256(message)
  sig.hash = base.encode16(hash)
  sig.verified = crypto.ecdsa.verify(signature, hash, pubkey, {encoding = 'binary', hash = true})

  -- Add signature to state
  state.signatures = state.signatures or {}
  table.insert(state.signatures, sig)

  return state
end
