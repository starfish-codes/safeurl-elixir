# Elixir < 1.15 does not start optional dependencies.
{:ok, _apps} = Application.ensure_all_started(:hackney)

ExUnit.start()
