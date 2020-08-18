defmodule Crypto.ParentChildSigVerifyTapeTest do
  use ExUnit.Case
  alias Operate.VM

  setup_all do
    tx = %{
      "h" => "test",
      "in" => [],
      "out" => [
        %{},
        %{
          "i" => "0",
          "tape" => [
            %{
              "i" => 0,
              "cell" => [
                %{"i" => 0, "ii" => 0, "op" => 0, "ops" => "OP_FALSE"},
                %{"i" => 1, "ii" => 1, "op" => 106, "ops" => "OP_RETURN"}
              ]
            },
            %{
              "i" => 1,
              "cell" => [
                %{"i" => 0, "ii" => 2, "b" => "Zm9v", "s" => "foo"},
                %{"i" => 1, "ii" => 3, "b" => "YmFy", "s" => "bar"}
              ]
            }
          ]
        }
      ]
    }

    vm = VM.init
    |> VM.set!("ctx.tx", tx)
    |> VM.set!("ctx.tape_index", 0)

    %{
      vm: vm,
      op: File.read!("src/crypto/parent_child_sig_verify_tape.lua")
    }
  end


  describe "simple example without signed content" do
    test "must set the correct attributes", ctx do
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "##dummy_sig2##", "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")

      assert res["parent"]["hash"] == "49659874a1dd58cb2e244d5686f8f2723fbe636475ce1649bf93cc3d1cc56b9f"
      assert res["parent"]["signature"] == "##dummy_sig1##"
      assert res["parent"]["pubkey"] == "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
      assert res["parent"]["verified"] == false
      assert res["child"]["hash"] == "20c231fd924816f4485216ea26e51e876033256a91e3dccc371dda4d00a7d078"
      assert res["child"]["signature"] == "##dummy_sig2##"
      assert res["child"]["pubkey"] == "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"
      assert res["child"]["verified"] == false
    end

    test "must raise when either pubkey is missing", ctx do
      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["1", "##dummy_sig1##", nil, "##dummy_sig2##", "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["1", "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "##dummy_sig2##", nil]}
        |> Operate.Cell.exec!(ctx.vm)
      end
    end

    test "must raise when either signature is missing", ctx do
      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["1", nil, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "##dummy_sig2##", "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["1", "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", nil, "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
        |> Operate.Cell.exec!(ctx.vm)
      end
    end

    test "must raise when tape index is missing", ctx do
      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: [nil, "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "##dummy_sig2##", "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
        |> Operate.Cell.exec!(ctx.vm)
      end
    end
  end


  describe "verifying a signature" do
    test "must verify a correct signature", ctx do
      sig1 = "H9o/19warnGfa1dfblvYLQFKCQa+KLnegyuCTAtR5wwuM/PKqCOvrWUgnVOd4QOq48AjAQ1ej+P6aPf6kHe8I78="
      sig2 = "IPIeRTkp48ykrrXmW7OBry8/uA0o8mLQF4Kvu7urhV1CPz67urWhK1epgqEL8Z1uZV4OIxYuzs5JAli1YS0+Is4="
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", sig1, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", sig2, "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")

      assert res["parent"]["verified"] == true
      assert res["child"]["verified"] == true
    end

    test "must verify with raw signatures", ctx do
      sig1 = Base.decode64! "H9o/19warnGfa1dfblvYLQFKCQa+KLnegyuCTAtR5wwuM/PKqCOvrWUgnVOd4QOq48AjAQ1ej+P6aPf6kHe8I78="
      sig2 = Base.decode64! "HwLB8rDyUwhVAOGailt2gqqA+fRhRy/G79quYHp/+ZZrd72mv1ynH9IdmN2gznQUyDp8deYZG/O3uGUaEZlmulU="
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", sig1, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", sig2, "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")

      assert res["parent"]["verified"] == true
      assert res["child"]["verified"] == true
    end
  end

end