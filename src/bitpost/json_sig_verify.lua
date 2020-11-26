--[[
Verifies a signature with the given public key against the given JSON string
payload.

The `payload` paramater must be a JSON string and will be decoded and added to
the state on the `data` attribute.

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
        "{\"key\":{\"host\":\"bitpost.app\",\"pubkey\":\"03028c57f62a1b834b0bc8b36366a89652806b08f32dc3a793d8e4d02f7cf92536\",\"uid\":1,\"username\":\"test\"},\"service\":{\"name\":\"moneybutton.com\",\"paymail\":\"test@moneybutton.com\",\"pubkey\":\"03e4cc0c595cee4e117203fe9c5cc5f8fcfbfa00a06f8048347c6c08c78f073a49\"},\"type\":\"paymail_link\",\"timestamp\":1606392500}"
        "IAsT/WgukyJMnhuVxpOpxEmr3be32H85m2ffFBzeJpuBKge+JjwtqryQUSHkV2d4yuYuoGJKgU/N7NrR+7U3juY="
        0x03028c57f62a1b834b0bc8b36366a89652806b08f32dc3a793d8e4d02f7cf92536
    # {
    #   data: {
    #     key: {
    #       host: "bitpost.app",
    #       pubkey: "03028c57f62a1b834b0bc8b36366a89652806b08f32dc3a793d8e4d02f7cf92536",
    #       uid: 1,
    #       username: "test",
    #     },
    #     service: {
    #       name: "moneybutton.com",
    #       paymail: "test@moneybutton.com",
    #       pubkey: "03e4cc0c595cee4e117203fe9c5cc5f8fcfbfa00a06f8048347c6c08c78f073a49"
    #     },
    #     type: "paymail_link",
    #     timestamp: 1606392500
    #   },
    #   signatures: [{
    #     message: "{\"key\":{\"host\":\"bitpost.app\",\"pubkey\":\"03028c57f62a1b834b0bc8b36366a89652806b08f32dc3a793d8e4d02f7cf92536\",\"uid\":1,\"username\":\"test\"},\"service\":{\"name\":\"moneybutton.com\",\"paymail\":\"test@moneybutton.com\",\"pubkey\":\"03e4cc0c595cee4e117203fe9c5cc5f8fcfbfa00a06f8048347c6c08c78f073a49\"},\"type\":\"paymail_link\",\"timestamp\":1606392500}",
    #     signature: "IAsT/WgukyJMnhuVxpOpxEmr3be32H85m2ffFBzeJpuBKge+JjwtqryQUSHkV2d4yuYuoGJKgU/N7NrR+7U3juY=",
    #     pubkey: "03028c57f62a1b834b0bc8b36366a89652806b08f32dc3a793d8e4d02f7cf92536",
    #     verified: true,
    #   }]
    # }

@version 0.1.0
@author Bitpost
]]--
return function(state, payload, signature, pubkey)
  state = state or {}

  -- Local helper method to determine if a string is blank
  local function isblank(str)
    return str == nil or str == ''
  end

  assert(
    type(state) == 'table',
    'Invalid state. Must be a table.')
  assert(
    not isblank(payload),
    'Invalid parameters. Payload must be present.')
  assert(
    not isblank(signature),
    'Invalid parameters. Signature must be present.')
  assert(
    not isblank(pubkey),
    'Invalid parameters. Pubkey must be present.')

  -- Build the signature object
  local sig = {
    message = payload,
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
  sig.verified = crypto.bitcoin_message.verify(signature, payload, pubkey, {encoding = 'binary'})

  -- Add decoded data payload to state
  state.data = json.decode(payload)

  -- Add signature to state
  state.signatures = state.signatures or {}
  table.insert(state.signatures, sig)

  return state
end
