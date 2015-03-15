defmodule PlugAuth.Authentication.Database do
  @moduledoc """
    Implements basic HTTP authentication. To use add:

      plug PlugAuth.Authentication.Basic, realm: "Secret world"

    to your pipeline. This module is derived from https://github.com/lexmag/blaguth
  """ 

  require Logger
  @session_key "database_auth"

  @behaviour Plug
  import Plug.Conn
  import PlugAuth.Authentication.Utils

  @doc """
    Add the credentials for a `user` and `password` combination. `user_data` can be any term but must not be `nil`.
  """
  def create_login(conn, user_data) do
    id = UUID.uuid1
    id |> PlugAuth.CredentialStore.put_credentials(user_data)
    put_session(conn, @session_key, id)
  end

  @doc """
    Remove the credentials for a `user` and `password` combination.
  """
  def delete_login(conn) do
    case get_session(conn, @session_key) do
      nil -> conn

      key -> 
        PlugAuth.CredentialStore.delete_credentials(key)
        put_session(conn, @session_key, nil)
    end
    |> delete_token_session 
  end

  defp delete_token_session(conn) do
    case get_session(conn, param_key) do
      nil -> conn
      param -> put_session(conn, param, nil)
    end
  end

  def get_user_data(conn) do
    get_session(conn, @session_key)
    |> PlugAuth.CredentialStore.get_user_data
  end

  def init(opts) do
    error = Keyword.get(opts, :error, "HTTP Authentication Required")
    login = Keyword.get(opts, :login)
    unless login do
      raise RuntimeError, message: "PlugAuth.Database requires a login redirect callback"
    end
    # Logger.warn "#{__MODULE__} init #{inspect opts}"
    %{login: login,  error: error}
  end

  def call(conn, opts) do
    # Logger.warn "#{__MODULE__} call #{inspect opts}"
    unless get_authenticated_user(conn) do
      conn
      |> get_session_data
      |> verify_auth_key
      |> assert_login(opts[:login])
    else
      conn
    end
  end

  def get_session_data(conn) do
    {conn, get_session(conn, @session_key) }
  end

  def verify_auth_key({conn, nil}) do
    # Logger.warn "#{__MODULE__} verify nil auth key"
    {conn, nil}
  end
  def verify_auth_key({conn, auth_key}) do
    # Logger.warn "#{__MODULE__} verify found auth key"
    {conn, PlugAuth.CredentialStore.get_user_data(auth_key)}
  end

  def assert_login({conn, nil}, login) do
    # Logger.warn "#{__MODULE__} assert needs login" # conn: #{inspect conn}"
    login.(conn)
  end

  def assert_login({conn, user_data}, login), do: assign_user_data(conn, user_data)

end
