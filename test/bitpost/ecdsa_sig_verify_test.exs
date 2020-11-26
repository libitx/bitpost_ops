defmodule Bitpost.ECDSASigVerifyTest do
  use ExUnit.Case
  alias Operate.VM

  setup_all do
    %{
      vm: VM.init,
      op: File.read!("src/bitpost/ecdsa_sig_verify.lua"),
    }
  end


  describe "simple example without signed content" do
    test "must set the correct attributes", ctx do
      res = %Operate.Cell{op: ctx.op, params: ["foobar", "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["hash"] == "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"
      assert res["signature"] == "##dummy_sig1##"
      assert res["pubkey"] == "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
      assert res["verified"] == false
    end

    test "must raise when message, signature or pubkey are missing", ctx do
      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: [nil, "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["foobar", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["foobar", "##dummy_sig1##", nil]}
        |> Operate.Cell.exec!(ctx.vm)
      end
    end
  end


  describe "verifying a signature" do
    setup do
      %{
        sig: "MEUCIQD2CFpfjhF65pOZEMSQ7KAIBWpG/CXMzhi2Q72dFybj3AIgbHDmUoAv1zS74PVJgiPSyjanEqp+TdxNcEeSDfvfvEg=",
        pubkey: "03d8464bc9999e106945298d93cc35e51fb6dbc21c05c0f4b25cb4d22d5d7d9613"
      }
    end

    test "must verify a correct signature", ctx do
      res = %Operate.Cell{op: ctx.op, params: ["95Wsv5lAHJMuOa-v6SJg6ld_P6EzbemwTGdgVSuM4fw", ctx.sig, ctx.pubkey]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end

    test "must verify with raw signature", ctx do
      res = %Operate.Cell{op: ctx.op, params: ["95Wsv5lAHJMuOa-v6SJg6ld_P6EzbemwTGdgVSuM4fw", Base.decode64!(ctx.sig), ctx.pubkey]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end

    test "must verify with raw pubkey", ctx do
      res = %Operate.Cell{op: ctx.op, params: ["95Wsv5lAHJMuOa-v6SJg6ld_P6EzbemwTGdgVSuM4fw", ctx.sig, Base.decode16!(ctx.pubkey, case: :lower)]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end
  end

end
