defmodule Bitpost.JsonSigVerifyTest do
  use ExUnit.Case
  alias Operate.VM

  setup_all do
    %{
      vm: VM.init,
      op: File.read!("src/bitpost/json_sig_verify.lua"),
      payload: "{\"key\":{\"host\":\"bitpost.app\",\"pubkey\":\"03028c57f62a1b834b0bc8b36366a89652806b08f32dc3a793d8e4d02f7cf92536\",\"uid\":1,\"username\":\"test\"},\"service\":{\"name\":\"moneybutton.com\",\"paymail\":\"test@moneybutton.com\",\"pubkey\":\"03e4cc0c595cee4e117203fe9c5cc5f8fcfbfa00a06f8048347c6c08c78f073a49\"},\"type\":\"paymail_link\",\"timestamp\":1606392500}"
    }
  end


  describe "simple example without signed content" do
    test "must set the correct attributes", ctx do
      res = %Operate.Cell{op: ctx.op, params: [ctx.payload, "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
      |> Operate.Cell.exec!(ctx.vm)

      sig = res
      |> Map.get("signatures")
      |> List.first

      assert res["data"]["key"]["host"] == "bitpost.app"
      assert sig["message"] == ctx.payload
      assert sig["signature"] == "##dummy_sig1##"
      assert sig["pubkey"] == "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
      assert sig["verified"] == false
    end

    test "must raise when payload, signature or pubkey are missing", ctx do
      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: [nil, "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: [ctx.payload, nil, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: [ctx.payload, "##dummy_sig1##", nil]}
        |> Operate.Cell.exec!(ctx.vm)
      end
    end
  end


  describe "verifying a signature" do
    setup do
      %{
        sig: "IAsT/WgukyJMnhuVxpOpxEmr3be32H85m2ffFBzeJpuBKge+JjwtqryQUSHkV2d4yuYuoGJKgU/N7NrR+7U3juY=",
        pubkey: "03028c57f62a1b834b0bc8b36366a89652806b08f32dc3a793d8e4d02f7cf92536"
      }
    end

    test "must verify a correct signature", ctx do
      res = %Operate.Cell{op: ctx.op, params: [ctx.payload, ctx.sig, ctx.pubkey]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end

    test "must verify with raw signature", ctx do
      res = %Operate.Cell{op: ctx.op, params: [ctx.payload, Base.decode64!(ctx.sig), ctx.pubkey]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end

    test "must verify with raw pubkey", ctx do
      res = %Operate.Cell{op: ctx.op, params: [ctx.payload, ctx.sig, Base.decode16!(ctx.pubkey, case: :lower)]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end
  end

end
