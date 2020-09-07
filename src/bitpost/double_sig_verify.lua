--[[
Verifies both a parent and child timestamped signatures with the given public
keys. Using two signatures allows Metanet-like tx graphs to be created, without
need to sign inputs and with more flexible ownership properties.

The message the parent signature is verified against is all of the script data
from the specified output index, hashed using the SHA-256 algorithm, and
appended with a 64 bit timestamp.

    sign(sha256(output)++timestamp)

The child signature is verified against  a subscript made from the `tape_idx`,
`parent_sig` and `parent_pubkey` parameters, hashed and then appented with the
64 bit timestamp.

    sign(sha256(script(tape_idx, parent_sig, parent_pubkey))++timestamp)

The `tape_idx` parameter is the output index of the tape containg the data to
verify the parent signature against. The value can either be utf8 encoded or an
unsigned integer.

The `parent_sig` and `child_sig` paramaters can be in either of the following
formats:

  * Raw 65 byte binary signature
  * Base64 encoded string

The `parent_pubkey` and `child_pubkey` parameters can be in any of the following
formats:

  * Raw 33 byte binary public key
  * Hex encoded string
  * A Bitcoin address string

The `timestamp` is a linux timestamp given as either a utf-8 encoded string or a
64-bit unsigned integer. The timestamp is optional.

## Examples

    OP_FALSE OP_RETURN
      $REF
        "1"
        "H0c7y0zWNIQ01IFlgOa3pvEuGIDe53Rc+4ogWyIha/OhWpkg83qNG7tr19XBLc1BSOwbauSRVWi12ncN1jye+iA="
        "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
        "IKUI7KdayvS/BKgXlTnAj4Re4C8Ew/AJ9HdwectCSKQJKXQZchxpbC5wHbYKcbk0Ol7yUSYKOCf9ibCFjsPfatE="
        "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"
        "1599495325"
    # {
    #   signatures: {
    #     parent: {
    #       hash: "4c2845d2977729bee395f12792d771d7f4b0786ca37ee9d5f5bcdf99581338d7",
    #       signature: "H0c7y0zWNIQ01IFlgOa3pvEuGIDe53Rc+4ogWyIha/OhWpkg83qNG7tr19XBLc1BSOwbauSRVWi12ncN1jye+iA=",
    #       pubkey: "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF",
    #       timestamp: 1599495325,
    #       verified: true,
    #     },
    #     child: {
    #       hash: "677ae98e74ebe6d68f93440bf2ebebdf35d7645a28c44220c88cab430b3b5734",
    #       signature: "IKUI7KdayvS/BKgXlTnAj4Re4C8Ew/AJ9HdwectCSKQJKXQZchxpbC5wHbYKcbk0Ol7yUSYKOCf9ibCFjsPfatE=",
    #       pubkey: "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd",
    #       timestamp: 1599495325,
    #       verified: true,
    #     },
    #   }
    # }

@version 0.2.0
@author Bitpost
]]--
return function(state, tape_idx, parent_sig, parent_pubkey, child_sig, child_pubkey, timestamp)
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
    not isblank(parent_sig) and not isblank(parent_pubkey),
    'Invalid parameters. Parent signature and pubkey must be present.')
  assert(
    not isblank(child_sig) and not isblank(child_pubkey),
    'Invalid parameters. Child signature and pubkey must be present.')

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

  -- If the timestamp is utf8 encoded then decode to binary string
  if string.len(timestamp) > 8 and string.match(timestamp, '^%d+$') then
    timestamp = math.floor(tonumber(timestamp))
    timestamp = string.pack('>I8', timestamp)
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
    sig.parent.verified = crypto.bitcoin_message.verify(
      parent_sig,
      hash1..timestamp,
      parent_pubkey,
      {encoding = 'binary'}
    )

    -- Build child sig from parent signature params
    local message2 = pushint(tape_idx) .. string.pack('B', tape_idx)
    message2 = message2 .. pushint(string.len(parent_sig)) .. parent_sig
    message2 = message2 .. pushint(string.len(parent_pubkey)) .. parent_pubkey
    local hash2 = crypto.hash.sha256(message2)
    sig.child.hash = base.encode16(hash2)
    sig.child.verified = crypto.bitcoin_message.verify(
      child_sig,
      hash2..timestamp,
      child_pubkey,
      {encoding = 'binary'}
    )
  end

  -- Add timestamp to sig table
  if string.len(timestamp) == 8 then
    timestamp = table.unpack(string.unpack('>I8', timestamp))
  end
  sig.parent.timestamp = timestamp
  sig.child.timestamp = timestamp

  -- Add signature to state
  state.signatures = state.signatures or {}
  state.signatures.parent = sig.parent
  state.signatures.child = sig.child

  return state
end
