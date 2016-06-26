defmodule Ueberauth.Strategy.Shopify do
  use Ueberauth.Strategy,
    default_scope: "read_products"

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Strategy.Helpers
  alias Ueberauth.Strategy.Shopify.OAuth, as: ShopifyOAuth

  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    opts = [
      redirect_uri: callback_url(conn),
      shop: conn.params["shop"]
    ]
    IO.inspect opts
    authorize_url = ShopifyOAuth.authorize_url!([scope: scopes], opts)

    redirect!(conn, authorize_url)
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: callback_url(conn), shop: conn.params["shop"]]
    token = ShopifyOAuth.get_token!([code: code], opts)

    if token.access_token == nil do
      err = token.other_params["error"]
      desc = token.other_params["error_description"]
      set_errors!(conn, [error(err, desc)])
    else
      conn
      |> put_private(:shopify_token, token)
      |> put_private(:shopify_shop, conn.params["shop"])
    end
  end

  def credentials(conn) do
    token = conn.private.shopify_token
    scopes =
      token.other_params["scope"]
      |> String.split(", ")

    %Credentials{
      scopes: scopes,
      token: token.access_token
    }
  end

  def uid(conn) do
    conn.params["shop"]
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.shopify_token,
        user: conn.private.shopify_shop
      }
    }
  end

  defp option(conn, key) do
    Dict.get(options(conn), key, Dict.get(default_options, key))
  end
end
