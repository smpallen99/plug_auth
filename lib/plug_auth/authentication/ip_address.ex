defmodule PlugAuth.Authentication.IpAddress do
  @moduledoc """
    Implements ip address based authentication. To use add

      plug PlugAuth.Authentication.IpAddress, allow: ~w(127.0.0.1 192.168.1.200) 

    to your pipeline.
  """ 

  @behaviour Plug
  import Plug.Conn
  import PlugAuth.Authentication.Utils
  require Logger
  alias PlugAuth.Authentication.Utils

  def init(opts) do
    allow = Keyword.get(opts, :allow, [])
    error = Keyword.get(opts, :error, "Unauthorized IP Address")
    %{allow: allow, error: error}
  end

  def call(conn, %{allow: allow, error: error}) do
    ip = conn.peer |> elem(0) |> Utils.to_string
    if ip in allow do
      conn
    else
      Logger.warn "Unauthorized access from IP #{ip}"
      halt_with_error(conn, error)
    end
  end
end
