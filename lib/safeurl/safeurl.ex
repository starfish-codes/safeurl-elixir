defmodule SafeURL do
  @moduledoc """
  `SafeURL` is library for mitigating Server Side Request
  Forgery vulnerabilities in Elixir. Private/reserved IP
  addresses are blocked by default, and users can add
  additional CIDR ranges to the blocklist, or alternatively
  allow specific CIDR ranges to which the application is
  allowed to make requests.

  You can use `allowed?/2` or `validate/2` to check if a
  URL is safe to call, and `pin/2` to get a URL that connects
  to the very address that passed validation.


  ## Examples

      iex> SafeURL.allowed?("https://includesecurity.com")
      true

      iex> SafeURL.validate("http://google.com/", schemes: ~w[https])
      {:error, :unsafe_scheme}

      iex> SafeURL.validate("http://230.10.10.10/")
      {:error, :unsafe_reserved}

      iex> SafeURL.validate("http://230.10.10.10/", block_reserved: false)
      :ok

      iex> SafeURL.pin("https://includesecurity.com/robots.txt")
      {:ok,
       %{
         url: "https://192.0.78.24/robots.txt",
         hostname: "includesecurity.com",
         address: {192, 0, 78, 24},
         scheme: "https",
         port: 443
       }}

      # If HTTPoison is available:

      iex> SafeURL.HTTPoison.get("https://10.0.0.1/ssrf.txt")
      {:error, :unsafe_reserved}

      iex> SafeURL.HTTPoison.get("https://google.com/")
      {:ok, %HTTPoison.Response{...}}


  ## Validation

  The host of the URL is resolved once, and every address it
  resolves to (IPv4 and IPv6) has to pass the allowlist or the
  blocklist. A host that does not resolve to any address is
  rejected with `:unresolved_host` rather than let through.

  IPv4-mapped (`::ffff:10.0.0.1`) and IPv4-compatible (`::10.0.0.1`)
  addresses are checked as the IPv4 address they carry.


  ## Pinning

  Validating a hostname and then handing that hostname to an HTTP
  client resolves it twice, and the second lookup can return a
  different address than the one that was checked (DNS rebinding).
  `pin/2` returns the URL with the host replaced by the validated
  address, together with the original hostname, so the client
  connects to the checked address and still sends the right `Host`
  header, SNI and certificate hostname:

      {:ok, %{url: url, hostname: hostname}} = SafeURL.pin("https://example.com/data")
      Req.get!(url, connect_options: [hostname: hostname])


  ## Options

  `SafeURL` can be configured to customize and override
  validation behaviour by passing the following options:

    * `:block_reserved` - Block reserved/private IP ranges.
      Defaults to `true`.

    * `:blocklist` - List of CIDR ranges to block. This is
      additive with `:block_reserved`. Defaults to `[]`.

    * `:allowlist` - List of CIDR ranges to allow. If
      specified, blocklist will be ignored. Defaults to `[]`.

    * `:schemes` - List of allowed URL schemes. Defaults to
      `["http, "https"]`.

    * `:dns_module` - Any module that implements the
      `SafeURL.DNSResolver` behaviour. Defaults to `SafeURL.DNS`,
      which looks up A and AAAA records with the `:dns` package.

    * `:detailed_error` - Return specific error if validation fails. If set to
      `false`, `validate/2` will return `{:error, :restricted}` regardless of
      the reason. Defaults to `true`.


  If `:block_reserved` is `true` and additional hosts/ranges
  are supplied with `:blocklist`, both of them are included in
  the final blocklist to validate the address. If allowed
  ranges are supplied with `:allowlist`, all blocklists are
  ignored and any hosts not explicitly declared in the allowlist
  are rejected.

  These options can be set globally in your `config.exs` file:

      config :safeurl,
        block_reserved: true,
        blocklist: ~w[100.0.0.0/16],
        schemes: ~w[https],
        dns_module: MyCustomDNSResolver

  Or they can be passed to the function directly, overriding any
  global options if set:

      iex> SafeURL.validate("http://10.0.0.1/", block_reserved: false)
      :ok

      iex> SafeURL.validate("https://app.service/", allowlist: ~w[170.0.0.0/24])
      :ok

      iex> SafeURL.validate("https://app.service/", blocklist: ~w[170.0.0.0/24])
      {:error, :unsafe_blocklist}

  """

  import Bitwise

  # Every block IANA marks as not globally reachable, in both families.
  # IPv4-mapped and IPv4-compatible addresses are not listed: normalize/1
  # rewrites them to the IPv4 address they carry before they are matched.
  @reserved_ranges Enum.map(
                     ~w[
                       0.0.0.0/8
                       10.0.0.0/8
                       100.64.0.0/10
                       127.0.0.0/8
                       169.254.0.0/16
                       172.16.0.0/12
                       192.0.0.0/24
                       192.0.2.0/24
                       192.88.99.0/24
                       192.168.0.0/16
                       198.18.0.0/15
                       198.51.100.0/24
                       203.0.113.0/24
                       224.0.0.0/4
                       240.0.0.0/4
                       ::/128
                       ::1/128
                       ::ffff:0:0:0/96
                       64:ff9b::/96
                       64:ff9b:1::/48
                       100::/64
                       100:0:0:1::/64
                       2001::/23
                       2001:db8::/32
                       2002::/16
                       2620:4f:8000::/48
                       3fff::/20
                       5f00::/16
                       fc00::/7
                       fe80::/10
                       fec0::/10
                       ff00::/8
                     ],
                     &InetCidr.parse_cidr!/1
                   )

  @type error() ::
          :unsafe_scheme
          | :unsafe_allowlist
          | :unsafe_blocklist
          | :unsafe_reserved
          | :unresolved_host

  @type pinned() :: %{
          url: binary(),
          hostname: binary(),
          address: :inet.ip_address(),
          scheme: binary(),
          port: :inet.port_number()
        }

  # Public API
  # ----------

  @doc """
  Validate a string URL against a blocklist or allowlist.

  This method checks if a URL is safe to be called by looking at
  its scheme and resolved IP addresses, and matching them against
  reserved CIDR ranges, and any provided allowlist/blocklist.

  Returns `true` if the URL meets the requirements,
  `false` otherwise.

  ## Examples

      iex> SafeURL.allowed?("https://includesecurity.com")
      true

      iex> SafeURL.allowed?("http://10.0.0.1/")
      false

      iex> SafeURL.allowed?("http://10.0.0.1/", allowlist: ~w[10.0.0.0/8])
      true

  ## Options

  See [`Options`](#module-options) section above.

  """
  @spec allowed?(binary(), Keyword.t()) :: boolean()
  def allowed?(url, opts \\ []) do
    case validate(url, opts) do
      :ok -> true
      {:error, _} -> false
    end
  end

  @doc """
  Alternative method of validating a URL, returning result tuple instead
  of booleans.

  If the URL is safe, it returns `:ok`, otherwise an error tuple with a
  specific reason. If `:detailed_error` is set to `false`, the error is always
  `{:error, :restricted}`.

  Prefer `pin/2` when you are about to make the request yourself, see
  [`Pinning`](#module-pinning).

  ## Examples

      iex> SafeURL.validate("https://includesecurity.com")
      :ok

      iex> SafeURL.validate("http://10.0.0.1/")
      {:error, :unsafe_reserved}

      iex> SafeURL.validate("http://10.0.0.1/", allowlist: ~w[10.0.0.0/8])
      :ok

  ## Options

  See [`Options`](#module-options) section above.

  """
  @spec validate(binary(), Keyword.t()) :: :ok | {:error, error()} | {:error, :restricted}
  def validate(url, opts \\ []) do
    with {:ok, _pinned} <- pin(url, opts) do
      :ok
    end
  end

  @doc """
  Validate a URL and return it pinned to the address that passed.

  The returned `:url` has the host replaced by the first validated
  address (the others are validated too, but not returned), `:hostname`
  is the host as it was in the URL, for the `Host` header, SNI and
  certificate verification, and `:address`, `:scheme` and `:port` are the
  parts a client needs to open the connection itself. Connecting to `:url` instead
  of the original one makes sure the request reaches the address that
  was checked, see [`Pinning`](#module-pinning).

  Errors are the same as for `validate/2`.

  ## Examples

      iex> SafeURL.pin("https://includesecurity.com/robots.txt")
      {:ok,
       %{
         url: "https://192.0.78.24/robots.txt",
         hostname: "includesecurity.com",
         address: {192, 0, 78, 24},
         scheme: "https",
         port: 443
       }}

      iex> SafeURL.pin("https://[::1]/")
      {:error, :unsafe_reserved}

  ## Options

  See [`Options`](#module-options) section above.

  """
  @doc since: "1.1.0"
  @spec pin(binary(), Keyword.t()) :: {:ok, pinned()} | {:error, error()} | {:error, :restricted}
  def pin(url, opts \\ []) do
    options = build_options(opts)

    url
    |> URI.parse()
    |> validate_and_pin(options)
    |> obscure_reason(options)
  end

  # Private Helpers
  # ---------------

  defp validate_and_pin(uri, opts) do
    with :ok <- validate_scheme(uri.scheme, opts),
         {:ok, addresses} <- resolve_addresses(uri.host, opts.dns_module),
         :ok <- validate_addresses(addresses, opts) do
      {:ok, pinned(uri, hd(addresses))}
    end
  end

  # Only the first address is handed back, but every one of them was checked,
  # so a caller that reaches for another is not reaching past validation.
  defp pinned(uri, address) do
    host =
      address
      |> :inet.ntoa()
      |> List.to_string()

    %{
      url: URI.to_string(%{uri | host: host}),
      hostname: uri.host,
      address: address,
      scheme: uri.scheme,
      port: uri.port
    }
  end

  # With :detailed_error off, a caller learns that the URL was refused and not
  # what about it was refused.
  defp obscure_reason(result, opts) do
    with {:error, _reason} <- result do
      if opts.detailed_error, do: result, else: {:error, :restricted}
    end
  end

  # Return a map of calculated options
  defp build_options(opts) do
    schemes = get_option(opts, :schemes)
    allowlist = parse_ranges(get_option(opts, :allowlist))
    blocklist = parse_ranges(get_option(opts, :blocklist))
    dns_module = get_option(opts, :dns_module)
    block_reserved = get_option(opts, :block_reserved)
    detailed_error = get_option(opts, :detailed_error)

    %{
      schemes: schemes,
      allowlist: allowlist,
      blocklist: blocklist,
      dns_module: dns_module,
      block_reserved: block_reserved,
      detailed_error: detailed_error
    }
  end

  # Get the value of a specific option, either from the application
  # configs or overrides explicitly passed as arguments.
  defp get_option(opts, key),
    do: Keyword.get_lazy(opts, key, fn -> Application.get_env(:safeurl, key) end)

  # Parsed once per call rather than once per address, like @reserved_ranges.
  defp parse_ranges(ranges), do: Enum.map(ranges, &InetCidr.parse_cidr!/1)

  defp validate_scheme(scheme, opts) do
    if scheme in opts.schemes, do: :ok, else: {:error, :unsafe_scheme}
  end

  # Resolve hostname in DNS to its IP addresses (if not already an IP).
  # A host without any address is an error: letting it through would
  # let the HTTP client connect to whatever it resolves to later.
  defp resolve_addresses(hostname, _dns_module) when hostname in [nil, ""] do
    {:error, :unresolved_host}
  end

  defp resolve_addresses(hostname, dns_module) do
    case :inet.parse_address(to_charlist(hostname)) do
      {:ok, ip} ->
        {:ok, [normalize(ip)]}

      {:error, :einval} ->
        resolve_in_dns(hostname, dns_module)
    end
  end

  # A resolver following a CNAME can hand back the target name next to the
  # addresses, so only the addresses are kept.
  defp resolve_in_dns(hostname, dns_module) do
    case dns_module.resolve(hostname) do
      {:ok, records} when is_list(records) -> only_addresses(records)
      _no_address -> {:error, :unresolved_host}
    end
  end

  defp only_addresses(records) do
    case Enum.filter(records, &is_tuple/1) do
      [] -> {:error, :unresolved_host}
      ips -> {:ok, Enum.map(ips, &normalize/1)}
    end
  end

  # An IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d) address
  # reaches the IPv4 host it carries, so it is checked as that IPv4 address.
  # The guard leaves out the unspecified and loopback addresses, which share
  # the compatible shape without carrying an IPv4 host.
  defp normalize({0, 0, 0, 0, 0, 0, high, low}) when high > 0 or low > 1 do
    embedded_ipv4(high, low)
  end

  defp normalize({0, 0, 0, 0, 0, 0xFFFF, high, low}) do
    embedded_ipv4(high, low)
  end

  defp normalize(ip), do: ip

  defp embedded_ipv4(high, low) do
    {high >>> 8, high &&& 0xFF, low >>> 8, low &&& 0xFF}
  end

  # Every address the host resolves to has to pass, otherwise a host with one
  # public and one internal address gets through on the public one.
  defp validate_addresses(addresses, opts) do
    Enum.reduce_while(addresses, :ok, fn address, :ok ->
      case validate_address(address, opts) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_address(address, opts) do
    cond do
      opts.allowlist != [] ->
        if ip_in_ranges?(address, opts.allowlist), do: :ok, else: {:error, :unsafe_allowlist}

      opts.blocklist != [] and ip_in_ranges?(address, opts.blocklist) ->
        {:error, :unsafe_blocklist}

      opts.block_reserved and ip_in_ranges?(address, @reserved_ranges) ->
        {:error, :unsafe_reserved}

      true ->
        :ok
    end
  end

  defp ip_in_ranges?(address, ranges) do
    Enum.any?(ranges, &InetCidr.contains?(&1, address))
  end
end
