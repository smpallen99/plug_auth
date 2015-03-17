defmodule PlugAuth.Authentication.Database do
  @moduledoc """
    Implements Database authentication. To use add:

      plug PlugAuth.Authentication.Database, login: &MyController.login_callback/1

    to your pipeline. This module is derived from https://github.com/lexmag/blaguth
  """ 

  @session_key Application.get_env(:plug_auth, :database_session_key, "database_auth")

  @behaviour Plug
  import Plug.Conn
  import PlugAuth.Authentication.Utils

  @doc """
    Create a login for a user. `user_data` can be any term but must not be `nil`.
  """
  def create_login(conn, user_data) do
    id = UUID.uuid1
    id |> PlugAuth.CredentialStore.put_credentials(user_data)
    put_session(conn, @session_key, id)
  end

  @doc """
    Delete a login.
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

  @doc """
    Fetch user data from the credential store
  """
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
    %{login: login,  error: error}
  end

  def call(conn, opts) do
    unless get_authenticated_user(conn) do
      conn
      |> get_session_data
      |> verify_auth_key
      |> assert_login(opts[:login])
    else
      conn
    end
  end

  defp get_session_data(conn) do
    {conn, get_session(conn, @session_key) }
  end

  defp verify_auth_key({conn, nil}), do: {conn, nil}
  defp verify_auth_key({conn, auth_key}), do: {conn, PlugAuth.CredentialStore.get_user_data(auth_key)}

  defp assert_login({conn, nil}, login), do: login.(conn)
  defp assert_login({conn, user_data}, login), do: assign_user_data(conn, user_data)

end
