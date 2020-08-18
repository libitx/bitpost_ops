defmodule Bitpost.Ops do
  use Mix.Project

  def project do
    [
      app: :bitpost_ops,
      version: "0.0.1",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:operate, "~> 0.1.0-beta"},
      {:luerl, github: "rvirding/luerl", branch: "develop", override: true},
      {:tesla, "~> 1.3"}
    ]
  end
end