defmodule SafeURLTest do
  use ExUnit.Case

  defmodule TestDNSResolver do
    @behaviour SafeURL.DNSResolver

    @impl true
    def resolve("mixed.example"), do: {:ok, [{192, 0, 78, 24}, {10, 0, 0, 1}]}
    def resolve("v6-only.example"), do: {:ok, [{0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111}]}

    def resolve("v6-internal.example"),
      do: {:ok, [{192, 0, 78, 24}, {0xFD00, 0, 0, 0, 0, 0, 0, 1}]}

    def resolve("cname.example"),
      do: {:ok, [~c"lb.example", {192, 0, 78, 24}, {192, 0, 78, 25}, ~c"lb.example"]}

    def resolve("cname-only.example"), do: {:ok, [~c"lb.example"]}
    def resolve("empty.example"), do: {:ok, []}
    def resolve("missing.example"), do: {:error, :nxdomain}
    def resolve(_domain), do: {:ok, [{192, 0, 78, 24}]}
  end

  describe "validate/2?" do
    test "returns true for only allowed schemes" do
      opts = [dns_module: TestDNSResolver]
      assert :ok = SafeURL.validate("http://includesecurity.com", opts)
      assert :ok = SafeURL.validate("https://includesecurity.com", opts)
      assert {:error, :unsafe_scheme} = SafeURL.validate("ftp://includesecurity.com", opts)

      opts = [schemes: ~w[ftp], dns_module: TestDNSResolver]
      assert :ok = SafeURL.validate("ftp://includesecurity.com", opts)
      assert {:error, :unsafe_scheme} = SafeURL.validate("http://includesecurity.com", opts)
    end

    test "returns false for reserved ranges" do
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://0.0.0.0/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://10.0.0.1/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://127.0.0.1/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://169.254.9.1/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://192.168.1.1/")
    end

    test "returns false for reserved IPv6 ranges" do
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[fd00::1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[fe80::1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[64:ff9b::a00:1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[2002:a00:1::]/")
    end

    test "checks an IPv4-mapped IPv6 address as the IPv4 address it carries" do
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::ffff:10.0.0.1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::ffff:a00:1]/")

      assert {:error, :unsafe_blocklist} =
               SafeURL.validate("http://[::ffff:5.5.5.5]/", blocklist: ["5.5.0.0/16"])

      assert :ok = SafeURL.validate("http://[::ffff:8.8.8.8]/")
    end

    test "checks an IPv4-compatible IPv6 address as the IPv4 address it carries" do
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::10.0.0.1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::127.0.0.1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::169.254.169.254]/")

      assert {:error, :unsafe_blocklist} =
               SafeURL.validate("http://[::5.5.5.5]/", blocklist: ["5.5.0.0/16"])

      assert :ok = SafeURL.validate("http://[::8.8.8.8]/")
    end

    test "keeps the unspecified and loopback addresses out of the IPv4 mapping" do
      assert {:ok, %{address: {0, 0, 0, 0, 0, 0, 0, 0}}} =
               SafeURL.pin("http://[::]/", block_reserved: false)

      assert {:ok, %{address: {0, 0, 0, 0, 0, 0, 0, 1}}} =
               SafeURL.pin("http://[::1]/", block_reserved: false)

      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::1]/")
    end

    test "blocks the IPv4-translated prefix" do
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::ffff:0:a00:1]/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://[::ffff:0:808:808]/")
    end

    test "blocks the IPv6 blocks IANA marks as not globally reachable" do
      for address <- ~w[
            100:0:0:1::1 2001::1 2001:1::1 2001:1::2 2001:1::3 2001:2::1 2001:3::1
            2001:4:112::1 2001:10::1 2001:20::1 2001:30::1 2001:db8::1 2002:a00:1::
            2620:4f:8000::1 3fff::1 5f00::1 fc00::1 fe80::1 fec0::1 ff00::1
          ] do
        assert {:error, :unsafe_reserved} = SafeURL.validate("http://[#{address}]/")
      end
    end

    test "allows routed public IPv6 addresses" do
      assert :ok = SafeURL.validate("http://[2606:4700:4700::1111]/")
      assert :ok = SafeURL.validate("http://[2001:200::1]/")
      assert :ok = SafeURL.validate("http://[2a00:1450:4001:800::200e]/")
    end

    test "every resolved address has to pass" do
      opts = [dns_module: TestDNSResolver]
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://mixed.example", opts)
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://v6-internal.example", opts)
      assert :ok = SafeURL.validate("http://v6-only.example", opts)
    end

    test "rejects a host without any address" do
      opts = [dns_module: TestDNSResolver]
      assert {:error, :unresolved_host} = SafeURL.validate("http://empty.example", opts)
      assert {:error, :unresolved_host} = SafeURL.validate("http://missing.example", opts)
      assert {:error, :unresolved_host} = SafeURL.validate("http:///path", opts)
      assert {:error, :unresolved_host} = SafeURL.validate("http://", opts)
    end

    test "returns true for reserved ranges if overridden" do
      opts = [block_reserved: false]

      assert :ok = SafeURL.validate("http://0.0.0.0/", opts)
      assert :ok = SafeURL.validate("http://10.0.0.1/", opts)
      assert :ok = SafeURL.validate("http://127.0.0.1/", opts)
      assert :ok = SafeURL.validate("http://169.254.9.1/", opts)
      assert :ok = SafeURL.validate("http://192.168.1.1/", opts)
    end

    test "blocking custom IP ranges" do
      opts = [blocklist: ["5.5.0.0/16", "100.0.0.0/24"], dns_module: TestDNSResolver]

      assert :ok = SafeURL.validate("http://includesecurity.com", opts)
      assert :ok = SafeURL.validate("http://3.3.3.3", opts)
      assert {:error, :unsafe_blocklist} = SafeURL.validate("http://5.5.5.5", opts)
      assert {:error, :unsafe_blocklist} = SafeURL.validate("http://100.0.0.50", opts)
    end

    test "only allows IPs in the allowlist when present" do
      opts = [allowlist: ["10.0.0.0/24"], dns_module: TestDNSResolver]

      assert :ok = SafeURL.validate("http://10.0.0.1/", opts)
      assert {:error, :unsafe_allowlist} = SafeURL.validate("http://72.254.45.178", opts)
      assert {:error, :unsafe_allowlist} = SafeURL.validate("https://includesecurity.com", opts)
    end

    test "detailed_errors can be switched off" do
      opts = [blocklist: ["5.5.0.0/16"], dns_module: TestDNSResolver, detailed_error: false]
      assert {:error, :restricted} = SafeURL.validate("ftp://includesecurity.com", opts)
      assert {:error, :restricted} = SafeURL.validate("http://5.5.5.5", opts)
      assert {:error, :restricted} = SafeURL.validate("http://0.0.0.0/", opts)
    end
  end

  describe "pin/2" do
    test "replaces the host with the validated address and keeps the hostname" do
      assert {:ok,
              %{
                url: "https://192.0.78.24:8443/data?x=1",
                hostname: "includesecurity.com",
                address: {192, 0, 78, 24}
              }} =
               SafeURL.pin("https://includesecurity.com:8443/data?x=1",
                 dns_module: TestDNSResolver
               )
    end

    test "keeps an address literal" do
      assert {:ok, %{url: "http://3.3.3.3/", hostname: "3.3.3.3", address: {3, 3, 3, 3}}} =
               SafeURL.pin("http://3.3.3.3/")
    end

    test "brackets an IPv6 address" do
      assert {:ok, %{url: "https://[2606:4700::1111]/", hostname: "v6-only.example"}} =
               SafeURL.pin("https://v6-only.example/", dns_module: TestDNSResolver)
    end

    test "pins the first address of a host behind a CNAME" do
      assert {:ok, %{url: "https://192.0.78.24/", address: {192, 0, 78, 24}}} =
               SafeURL.pin("https://cname.example/", dns_module: TestDNSResolver)
    end

    test "refuses a host whose CNAME resolves to no address" do
      assert {:error, :unresolved_host} =
               SafeURL.pin("https://cname-only.example/", dns_module: TestDNSResolver)
    end

    test "returns the validation error" do
      assert {:error, :unsafe_reserved} = SafeURL.pin("http://10.0.0.1/")
      assert {:error, :restricted} = SafeURL.pin("http://10.0.0.1/", detailed_error: false)
    end
  end
end
