defmodule Ueberauth.Strategy.Shopify.OAuth do
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__
  ]

  def client(opts) do
    app_config = Application.get_env(:ueberauth, Ueberauth.Strategy.Shopify.OAuth)
    base_url = "https://" <> Keyword.get(opts, :shop)
    url_options =
      [site: base_url,
       authorize_url: base_url <> "/admin/oauth/authorize",
       token_url: base_url <> "/admin/oauth/access_token"]

    oauth_config =
      @defaults
      |> Keyword.merge(app_config)
      |> Keyword.merge(url_options)

    OAuth2.Client.new(oauth_config)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  """
  def authorize_url!(params \\ [], opts) do
    client(opts)
    |> OAuth2.Client.authorize_url!(params)
  end

  def get_token!(params \\ [], opts \\ %{}) do
    client(opts)
    |> OAuth2.Client.get_token!(params)
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end
end
