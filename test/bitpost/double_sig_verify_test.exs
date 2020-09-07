defmodule Bitpost.DoubleSigVerifyTest do
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
      op: File.read!("src/bitpost/double_sig_verify.lua")
    }
  end


  describe "simple example without signed content" do
    test "must set the correct attributes", ctx do
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "##dummy_sig2##", "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd", "1599495325"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")

      assert res["parent"]["hash"] == "677ae98e74ebe6d68f93440bf2ebebdf35d7645a28c44220c88cab430b3b5734"
      assert res["parent"]["signature"] == "##dummy_sig1##"
      assert res["parent"]["pubkey"] == "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
      assert res["parent"]["timestamp"] == 1599495325
      assert res["parent"]["verified"] == false
      assert res["child"]["hash"] == "a3591af923ae39bb1082ec7003d058090ae864bc534080a95a06d6447ee378e0"
      assert res["child"]["signature"] == "##dummy_sig2##"
      assert res["child"]["pubkey"] == "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"
      assert res["child"]["timestamp"] == 1599495325
      assert res["child"]["verified"] == false
    end

    test "works consistently if index is an integer", ctx do
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: [<<1>>, "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "##dummy_sig2##", "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")

      assert res["parent"]["hash"] == "677ae98e74ebe6d68f93440bf2ebebdf35d7645a28c44220c88cab430b3b5734"
      assert res["child"]["hash"] == "a3591af923ae39bb1082ec7003d058090ae864bc534080a95a06d6447ee378e0"
    end

    test "must raise when tape index is missing", ctx do
      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: [nil, "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "##dummy_sig2##", "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
        |> Operate.Cell.exec!(ctx.vm)
      end
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
  end


  describe "verifying a signature" do
    test "must verify a correct signature", ctx do
      sig1 = "IF4c9E2d7d0eqkR7apt8ZGXpthYhb4eF6ifLp5gXbIsRTw5GzNmK2H7kMjP1nYez0l15R5fLz48HBfqMJEocHGE="
      sig2 = "ILCHj8gjJ1+7WKTcRQCPg+u4M85T3pjmUjJ01MSKZF0vZNGSCFnrAOBpPavBG+atZuQLyjrazxXx+/Jx9gJAvSQ="
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", sig1, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", sig2, "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")

      assert res["parent"]["verified"] == true
      assert res["child"]["verified"] == true
    end

    test "must verify with raw signatures", ctx do
      sig1 = Base.decode64! "IF4c9E2d7d0eqkR7apt8ZGXpthYhb4eF6ifLp5gXbIsRTw5GzNmK2H7kMjP1nYez0l15R5fLz48HBfqMJEocHGE="
      sig2 = Base.decode64! "ILCHj8gjJ1+7WKTcRQCPg+u4M85T3pjmUjJ01MSKZF0vZNGSCFnrAOBpPavBG+atZuQLyjrazxXx+/Jx9gJAvSQ="
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", sig1, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", sig2, "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")

      assert res["parent"]["verified"] == true
      assert res["child"]["verified"] == true
    end

    test "must verify a correct timestamped signature", ctx do
      sig1 = "IPOJjDEQC2s44zbZCEPpjjFUA6w8DmMbpqpijSn0k44xQco4AU0RBp2aBZ3H/KgV3+u0l3e6YFeVNOidT0z0nbY="
      sig2 = "H2htShuq1R0P+XeEPofNFz05LsOk6Eldi7c/KFyPBtiXN7XFlqPMjKGQ9jtxe/iuPX5LIg41Pj/lO3ws35s46iE="
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", sig1, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", sig2, "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd", "1599495325"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")

      assert res["parent"]["verified"] == true
      assert res["child"]["verified"] == true
    end

    test "wont verify an incorrect timestamped signature", ctx do
      sig1 = "IPOJjDEQC2s44zbZCEPpjjFUA6w8DmMbpqpijSn0k44xQco4AU0RBp2aBZ3H/KgV3+u0l3e6YFeVNOidT0z0nbY="
      sig2 = "H2htShuq1R0P+XeEPofNFz05LsOk6Eldi7c/KFyPBtiXN7XFlqPMjKGQ9jtxe/iuPX5LIg41Pj/lO3ws35s46iE="
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", sig1, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", sig2, "1KNiYtyWqjmR8DoC8e7xeMi2F1CwHcrdsd", "1599490000"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")

      assert res["parent"]["verified"] == false
      assert res["child"]["verified"] == false
    end
  end

end
