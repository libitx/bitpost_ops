--[[
Creates a simple file hash reference using the given parameters. The hash is
assumed to be a `SHA-256` hash, either as a raw binary or hex-encoded string.

## Examples

    OP_FALSE OP_RETURN
      $REF
        "text/plain"
        "Hello world"
    # {
    #   data: "Hello world",
    #   type: "text/plain"
    # }

@version 0.1.0
@author Bitpost
]]--
return function(state, mediatype, hash)
  state = state or {}
  assert(
    type(state) == 'table',
    'Invalid context. Must receive a table.')

  -- Local helper method to determine if a string is blank
  local function isblank(str)
    return str == nil or str == ''
  end

  assert(
    not isblank(mediatype) and not isblank(hash),
    'Invalid parameters.')

  -- Build the file hash object
  if string.len(hash) == 64 and string.match(hash, '^[a-fA-F0-9]+$') then
    state.hash = hash
  else
    state.hash = base.encode16(hash)
  end
  state.type = mediatype

  return state
end