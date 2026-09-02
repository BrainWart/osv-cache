using System.Buffers;
using System.IO.Pipelines;
using System.Text;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace API;

public static class ConnectTunnelExtensions {
    public static ListenOptions UseConnect(
        this ListenOptions options)
    {
        options.Use(next =>
        {
            ILoggerFactory loggerFactory
                = options.ApplicationServices.GetRequiredService<ILoggerFactory>();
            ILogger<ConnectTunnelMiddleware> logger
                = loggerFactory.CreateLogger<ConnectTunnelMiddleware>();
            ConnectTunnelMiddleware middleware = new(next, Array.Empty<string>(), logger);
            return middleware.OnConnectionAsync;
        });

        return options;
    }
}

public class ConnectTunnelMiddleware(
    ConnectionDelegate next,
    string[] allowedHosts,
    ILogger<ConnectTunnelMiddleware> logger
) {
    private static readonly byte[] ConnectMethod = "CONNECT "u8.ToArray();

    private static readonly byte[] ConnectionEstablished
        = "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();

    private static readonly byte[] BadRequest = "HTTP/1.1 400 Bad Request\r\n\r\n"u8.ToArray();
    private static readonly byte[] Forbidden = "HTTP/1.1 403 Forbidden\r\n\r\n"u8.ToArray();

    public async Task OnConnectionAsync(ConnectionContext context)
    {
        PipeReader input = context.Transport.Input;

        ReadResult result = await input.ReadAtLeastAsync(ConnectMethod.Length + 3);
        ReadOnlySequence<byte> buffer = result.Buffer;

        if (buffer.Length == 0)
        {
            return;
        }

        if (StartsWithConnect(buffer))
        {
            if (!TryParseConnectRequest(buffer, out string host, out int consumed))
            {
                await context.Transport.Output.WriteAsync(BadRequest);
                return;
            }

            await context.Transport.Output.WriteAsync(ConnectionEstablished);
            input.AdvanceTo(buffer.GetPosition(consumed));

            logger.LogInformation("CONNECT tunnel requested for {Host}", host);

            if (allowedHosts.Length > 0)
            {
                if (!allowedHosts.Contains(host))
                {
                    await context.Transport.Output.WriteAsync(Forbidden);
                    return;
                }
            }

            await next(context);
        }
        else
        {
            input.AdvanceTo(buffer.Start);
            await next(context);
        }
    }

    private static bool StartsWithConnect(ReadOnlySequence<byte> buffer)
    {
        if (buffer.Length < ConnectMethod.Length)
        {
            return false;
        }

        return buffer.FirstSpan
            .Slice(0, ConnectMethod.Length)
            .SequenceEqual(ConnectMethod);
    }

    private static bool TryParseConnectRequest(
        ReadOnlySequence<byte> buffer,
        out string host,
        out int consumed)
    {
        host = string.Empty;
        consumed = 0;

        SequenceReader<byte> reader = new(buffer);

        if (!reader.TryReadTo(out ReadOnlySpan<byte> requestLine, (byte)'\n'))
        {
            return false;
        }

        while (reader.TryReadTo(out ReadOnlySpan<byte> headerLine, (byte)'\n'))
        {
            if (reader.Remaining > 0)
            {
                string strLine = Encoding.ASCII.GetString(headerLine).TrimEnd();
                if (string.IsNullOrEmpty(strLine))
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }

        consumed = (int)reader.Consumed;

        // Parse "CONNECT host:port HTTP/1.1\r\n"
        string line = Encoding.ASCII.GetString(requestLine).TrimEnd('\r', '\n');
        string[] parts = line.Split(' ');

        if (parts.Length < 2)
        {
            return false;
        }

        host = parts[1];
        return true;
    }
}