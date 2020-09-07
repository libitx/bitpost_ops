defmodule Bitpost.SigVerifyTest do
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
      op: File.read!("src/bitpost/sig_verify.lua")
    }
  end


  describe "simple example without signed content" do
    test "must set the correct attributes", ctx do
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "1599495325"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["hash"] == "677ae98e74ebe6d68f93440bf2ebebdf35d7645a28c44220c88cab430b3b5734"
      assert res["signature"] == "##dummy_sig1##"
      assert res["pubkey"] == "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"
      assert res["verified"] == false
      assert res["timestamp"] == 1599495325
    end

    test "works consistently if index and timestamp is a binary integer", ctx do
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: [<<1>>, "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", <<0, 0, 0, 0, 95, 86, 92, 157>>]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["hash"] == "677ae98e74ebe6d68f93440bf2ebebdf35d7645a28c44220c88cab430b3b5734"
      assert res["timestamp"] == 1599495325
    end

    test "must raise when tape index is missing", ctx do
      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: [nil, "##dummy_sig1##", "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "1599495325"]}
        |> Operate.Cell.exec!(ctx.vm)
      end
    end

    test "must raise when signature or pubkey are missing", ctx do
      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["1", nil, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "1599495325"]}
        |> Operate.Cell.exec!(ctx.vm)
      end

      assert_raise RuntimeError, ~r/^Lua Error/, fn ->
        %Operate.Cell{op: ctx.op, params: ["1", "##dummy_sig1##", nil, "1599495325"]}
        |> Operate.Cell.exec!(ctx.vm)
      end
    end
  end


  describe "verifying a signature" do
    test "must verify a correct signature", ctx do
      sig = "IF4c9E2d7d0eqkR7apt8ZGXpthYhb4eF6ifLp5gXbIsRTw5GzNmK2H7kMjP1nYez0l15R5fLz48HBfqMJEocHGE="
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", sig, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end

    test "must verify a correct timestamped signature", ctx do
      sig = "H0c7y0zWNIQ01IFlgOa3pvEuGIDe53Rc+4ogWyIha/OhWpkg83qNG7tr19XBLc1BSOwbauSRVWi12ncN1jye+iA="
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", sig, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "1599495325"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end

    test "must verify with raw signatures", ctx do
      sig = Base.decode64! "H0c7y0zWNIQ01IFlgOa3pvEuGIDe53Rc+4ogWyIha/OhWpkg83qNG7tr19XBLc1BSOwbauSRVWi12ncN1jye+iA="
      res = %Operate.Cell{op: ctx.op, data_index: 0, params: ["1", sig, "1iCqLKPjv5HZ43MPkAC42vKPANLkGzbKF", "1599495325"]}
      |> Operate.Cell.exec!(ctx.vm)
      |> Map.get("signatures")
      |> List.first

      assert res["verified"] == true
    end
  end

end
