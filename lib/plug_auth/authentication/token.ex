defmodule PlugAuth.Authentication.Token do
  @moduledoc """
    Implements token based authentication. To use add

      plug PlugAuth.Authentication.Token, source: :params, param: "auth_token"

    or

      plug PlugAuth.Authentication.Token, source: :session, param: "auth_token"

    or

      plug PlugAuth.Authentication.Token, source: :header, param: "X-Auth-Token"    

    or

      plug PlugAuth.Authentication.Token, source: { module, function, ["my_param"]} end

    or

      plug PlugAuth.Authentication.Token, source: :params_session, param: "auth_token"

    to your pipeline.
  """ 

  @behaviour Plug
  import Plug.Conn
  import PlugAuth.Authentication.Utils
  require Logger

  @doc """
    Add the credentials for a `token`. `user_data` can be any term but must not be `nil`.
  """
  def add_credentials(token, user_data) do
    PlugAuth.CredentialStore.put_credentials(token, user_data)
  end

  @doc """
    Remove the credentials for a `token`.
  """
  def remove_credentials(token) do
    PlugAuth.CredentialStore.delete_credentials(token)
  end

  @doc """
    Utility function to generate a random authentication token.
  """
  def generate_token() do
    :crypto.strong_rand_bytes(16) |> Base.url_encode64
  end

  def init(opts) do
    param = Keyword.get(opts, :param)
    source = Keyword.fetch!(opts, :source) |> convert_source(param)
    error = Keyword.get(opts, :error, "HTTP Authentication Required")
    %{source: source, error: error}
  end

  defp convert_source(:params_session, param), do: {__MODULE__, :get_token_from_params_session, [param]}
  defp convert_source(:params, param), do: {__MODULE__, :get_token_from_params, [param]}
  defp convert_source(:header, param), do: {__MODULE__, :get_token_from_header, [param]}
  defp convert_source(:session, param), do: {__MODULE__, :get_token_from_session, [param]}
  defp convert_source(source = {module, fun, args}, _param) when is_atom(module) and is_atom(fun) and is_list(args), do: source

  def get_token_from_params(conn, param), do: {conn, conn.params[param]}
  def get_token_from_header(conn, param), do: {conn, get_first_req_header(conn, param)}
  def get_token_from_session(conn, param), do: {conn, get_session(conn, param)}

  def get_token_from_params_session(conn, param) do 
    get_token_from_params(conn, param)
    |> check_token_from_session(param)
    |> save_token_in_session(param)
  end
  def check_token_from_session({conn, nil}, param), do: get_token_from_session(conn, param)
  def check_token_from_session({conn, creds}, _param), do: {conn, creds}

  def save_token_in_session({conn, nil}, _), do: {conn, nil}
  def save_token_in_session({conn, creds}, param) do 
    {put_session(conn, param, creds) |> put_session(param_key, param), creds}
  end

  def call(conn, opts) do
    unless get_authenticated_user(conn) do
      {module, fun, args} = opts[:source]
      apply(module, fun, [conn | args])
      |> verify_creds
      |> assert_creds(opts[:error])
    else 
      conn
    end
  end

  defp verify_creds({conn, creds}), do: {conn, PlugAuth.CredentialStore.get_user_data(creds)}

  defp assert_creds({conn, nil}, nil), do: conn
  defp assert_creds({conn, nil}, error), do: halt_with_error(conn, error)
  defp assert_creds({conn, user_data}, _), do: assign_user_data(conn, user_data)
end

