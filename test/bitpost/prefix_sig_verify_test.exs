defmodule Bitpost.PrefixSigVerifyTest do
  use ExUnit.Case
  alias Operate.VM

  setup_all do
    %{
      vm: VM.init,
      op: File.read!("src/bitpost/prefix_sig_verify.lua"),
    }
  end


  describe "simple example without signed content" do
    test "must set the correct attributes", ctx do
      res = %Operate.Cell{op: ctx.op, params: ["foo", "bar", "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["message"] == "foo.bar"
      assert res["signature"] == "##dummy_sig1##"
      assert res["pubkey"] == "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
      assert res["verified"] == false
    end

    test "must raise when prefix, data, signature or pubkey are missing", ctx do
      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: [nil, "bar", "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["foo", nil, "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["foo", "bar", nil, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["foo", "bar", "##dummy_sig1##", nil]}
        |> Operate.Cell.exec!(ctx.vm)
      end
    end
  end


  describe "verifying a signature" do
    setup do
      %{
        sig: "H5SxczuULA8YKwM/SK20Wp6ucDsIZ9ZhS4S6niDP6pKKToozBf886nNEWTEx/KLVg8EXTj4sYGL9ebZFxe2ddA8=",
        pubkey: "03e4cc0c595cee4e117203fe9c5cc5f8fcfbfa00a06f8048347c6c08c78f073a49"
      }
    end

    test "must verify a correct signature", ctx do
      res = %Operate.Cell{op: ctx.op, params: ["1TEST", "95Wsv5lAHJMuOa-v6SJg6ld_P6EzbemwTGdgVSuM4fw", ctx.sig, ctx.pubkey]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end

    test "must verify with raw signature", ctx do
      res = %Operate.Cell{op: ctx.op, params: ["1TEST", "95Wsv5lAHJMuOa-v6SJg6ld_P6EzbemwTGdgVSuM4fw", Base.decode64!(ctx.sig), ctx.pubkey]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end

    test "must verify with raw pubkey", ctx do
      res = %Operate.Cell{op: ctx.op, params: ["1TEST", "95Wsv5lAHJMuOa-v6SJg6ld_P6EzbemwTGdgVSuM4fw", ctx.sig, Base.decode16!(ctx.pubkey, case: :lower)]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end
  end

end
