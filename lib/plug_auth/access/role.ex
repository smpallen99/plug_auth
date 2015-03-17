defmodule PlugAuth.Access.Role do
  @moduledoc """
    Implements role-based access control. Authentication must occur before access control.
    
    ## Example:
      plug PlugAuth.Authentication.Basic, realm: "Secret world"
      plug PlugAuth.Access.Role, roles: [:admin]
  """ 

  @behaviour Plug
  import Plug.Conn

  require Logger

  def init(opts) do
    roles = Keyword.fetch!(opts, :roles)
    error = Keyword.get(opts, :error, "HTTP Forbidden")
    %{roles: roles, error: error}
  end

  def call(conn, opts) do
    conn
    |> get_user
    |> get_role
    |> assert_role(opts[:roles], opts[:error])
  end

  defp get_user(conn) do 
    user_data = PlugAuth.Authentication.Utils.get_authenticated_user(conn)
    {conn, user_data}
  end
  defp get_role({conn, nil}), do: {conn, nil}
  defp get_role({conn, user}), do: {conn, PlugAuth.Access.RoleAdapter.get_role(user)}

  defp assert_role({conn, role}, roles, error) when is_list(role) do
    case Enum.filter(role, &(&1 in roles)) do
      [] -> 
        halt_forbidden(conn, error)
      found -> 
        assign(conn, :authenticated_role, found)
    end
  end

  defp assert_role({conn, role}, roles, error) do
    if role in roles do
      assign(conn, :authenticated_role, role)
    else
      halt_forbidden(conn, error)
    end
  end

  defp halt_forbidden(conn, error) do
    conn
    |> send_resp(403, error) 
    |> halt
  end
end
