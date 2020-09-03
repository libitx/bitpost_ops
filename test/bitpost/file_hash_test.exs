defmodule Bitpost.FileHashTest do
  use ExUnit.Case

  setup_all do
    %{
      vm: Operate.VM.init,
      op: File.read!("src/bitpost/file_hash.lua")
    }
  end
  
  test "must create a file hash object", ctx do
    res = %Operate.Cell{op: ctx.op, params: ["text/plain", "bf1cb99dbc32f3057929e1da7d2f623aaafb09dc1b3340b6f125fa525c2ec53a"]}
    |> Operate.Cell.exec!(ctx.vm)
    assert res == %{
      "hash" => "bf1cb99dbc32f3057929e1da7d2f623aaafb09dc1b3340b6f125fa525c2ec53a",
      "type" => "text/plain"
    }
  end

  test "must raise when any attributes are missing", ctx do
    assert_raise RuntimeError, ~r/^Lua Error/, fn ->
      %Operate.Cell{op: ctx.op, params: ["text/plain"]}
      |> Operate.Cell.exec!(ctx.vm)
    end
  end

  test "must handle binary hash", ctx do
    hash = <<191, 28, 185, 157, 188, 50, 243, 5, 121, 41, 225, 218, 125, 47, 98, 58, 170, 251, 9, 220, 27, 51, 64, 182, 241, 37, 250, 82, 92, 46, 197, 58>>
    res = %Operate.Cell{op: ctx.op, params: ["text/plain", hash]}
    |> Operate.Cell.exec!(ctx.vm)
    assert res == %{
      "hash" => "bf1cb99dbc32f3057929e1da7d2f623aaafb09dc1b3340b6f125fa525c2ec53a",
      "type" => "text/plain"
    }
  end

end
