defmodule Kazan.Client.Imp do
  @moduledoc false
  # Kazan.Client sends requests to a kubernetes server.
  # These requests should be built using the functions in the `Kazan.Apis` module.

  alias Kazan.{Request, Server}

  @httpoison_options Application.compile_env(:kazan, :httpoison_options, [])

  @type run_result :: {:ok, struct} | {:error, term}

  @doc """
  Makes a request against a kube server.

  The server should be set in the kazan config or provided in the options.

  ### Options

  * `server` - A `Kazan.Server` struct that defines which server we should send
  this request to. This will override any server provided in the Application
  config.
  """
  @spec run(Request.t(), Keyword.t()) :: run_result
  def run(%Request{} = request, options \\ []) do
    options = Map.new(options)
    server = find_server(options)

    headers = [{"Accept", "application/json"}] ++ content_type_header(request.content_type) ++ auth_headers(server.auth)
    request_options = [params: request.query_params, ssl: ssl_options(server)] ++ timeout_opts(options) ++ @httpoison_options
    request_options = case options do
      %{stream_to: pid} when is_pid(pid) ->
        request_options ++ [stream_to: pid, recv_timeout: Map.get(options, :recv_timeout, 15000)]
      _ -> request_options
    end

    HTTPoison.request(
      method(request.method),
      server.url <> request.path,
      request.body || "",
      headers,
      request_options
    )
    |> handle_response(request, options)
  end

  @doc """
  Like `run`, but raises on Error.  See `run/2` for more details.
  """
  @spec run!(Request.t(), Keyword.t()) :: struct | no_return
  def run!(%Request{} = request, options \\ []) do
    case run(request, options) do
      {:ok, result} -> result
      {:error, reason} -> raise Kazan.RemoteError, reason: reason
    end
  end

  defp handle_response({:ok, %HTTPoison.AsyncResponse{id: id}}, _, %{stream_to: pid}) when is_pid(pid), do: {:ok, id}
  defp handle_response(err, _, %{stream_to: pid}) when is_pid(pid), do: err
  defp handle_response({:ok, result}, request, _) do
    with {:ok, body} <- check_status(result),
         {:ok, content_type} <- get_content_type(result) do
      case content_type do
        "application/json" ->
          with {:ok, data} <- Poison.decode(body),
               {:ok, model} <- decode(data, request.response_model),
            do: {:ok, model}

        "text/plain" ->
          {:ok, body}

        _ ->
          {:error, :unsupported_content_type}
      end
    end
  end
  defp handle_response(err, _, _), do: err

  defp timeout_opts(%{recv_timeout: recv}), do: [recv_timeout: recv]
  defp timeout_opts(%{timeout: recv}), do: [recv_timeout: recv]
  defp timeout_opts(_), do: []

  # Figures out which server we should use.  In order of preference:
  # - A server specified in the keyword arguments
  # - A server specified in the kazan config
  @spec find_server(Keyword.t()) :: Server.t()
  defp find_server(%{server: %Server{} = server}), do: server
  defp find_server(opts) when is_list(opts), do: find_server(Map.new(opts))
  defp find_server(_), do: Server.from_env!()

  defp method("get"), do: :get
  defp method("post"), do: :post
  defp method("put"), do: :put
  defp method("delete"), do: :delete
  defp method("patch"), do: :patch

  @spec check_status(HTTPoison.Response.t()) :: {:ok, String.t()}
  defp check_status(%{status_code: code, body: body}) when code in 200..299 do
    {:ok, body}
  end

  defp check_status(%{status_code: other, body: body}) do
    data =
      case Poison.decode(body) do
        {:ok, data} -> data
        _ -> body
      end

    {:error, {:http_error, other, data}}
  end

  @spec get_content_type(HTTPoison.Response.t()) ::
          {:ok, String.t()} | {:error, :no_content_type}
  defp get_content_type(%{headers: headers}) do
    case List.keyfind(headers, "Content-Type", 0) do
      nil -> {:error, :no_content_type}
      {_, content_type} -> {:ok, content_type}
    end
  end

  @spec ssl_options(Server.t()) :: Keyword.t()
  defp ssl_options(server) do
    auth_options = ssl_auth_options(server.auth)

    verify_options =
      case server.insecure_skip_tls_verify do
        true -> [verify: :verify_none]
        _ -> []
      end

    ca_options =
      case server.ca_cert do
        nil -> []
        cert -> [cacerts: [cert], verify: :verify_peer]
      end

    auth_options ++ verify_options ++ ca_options
  end

  defp ssl_auth_options(%Server.CertificateAuth{certificate: cert, key: key}), do: [cert: cert, key: key]
  defp ssl_auth_options(_), do: []

  defp content_type_header(type) when is_binary(type), do: [{"Content-Type", type}]
  defp content_type_header(_), do: []

  defp auth_headers(%Server.TokenAuth{token: token}), do: [{"Authorization", "Bearer #{token}"}]
  defp auth_headers(%Server.ProviderAuth{token: token}) when not is_nil(token), do: [{"Authorization", "Bearer #{token}"}]
  defp auth_headers(%Server.BasicAuth{token: token}) when not is_nil(token), do: [{"Authorization", "Basic #{token}"}]
  defp auth_headers(%Server.ProviderAuth{}) do
    raise "Provider authentication needs resolved before use.  Please see Kazan.Server.resolve_auth/2 documentation for more details"
  end
  defp auth_headers(_), do: []

  # Decode helpers: if we know what model we're expecting, use that.
  # Otherwise defer to Kazan.Models.decode which will try to guess the model
  # from the kind provided in the response.
  defp decode(data, nil), do: Kazan.Models.decode(data, nil)
  defp decode(data, response_model), do: response_model.decode(data)
end
