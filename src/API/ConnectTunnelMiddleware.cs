using System.Buffers;
using System.IO.Pipelines;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace API;

public static class ConnectTunnelExtensions {
    public static ListenOptions UseConnect(
        this ListenOptions options, X509Certificate2 certificate)
    {
        options.Use(next =>
        {
            ILoggerFactory loggerFactory
                = options.ApplicationServices.GetRequiredService<ILoggerFactory>();
            ILogger<ConnectTunnelMiddleware> logger
                = loggerFactory.CreateLogger<ConnectTunnelMiddleware>();
            ConnectTunnelMiddleware middleware = new(next, Array.Empty<string>(), certificate, logger);
            return middleware.OnConnectionAsync;
        });

        return options;
    }
}

public class ConnectTunnelMiddleware(
    ConnectionDelegate next,
    string[] allowedHosts,
    X509Certificate2 certificate,
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

            // The client believes it now holds a direct connection to the tunneled host and
            // will start a TLS handshake targeting it, so terminate that handshake here before
            // handing off to the rest of the pipeline (plain-HTTP forward proxying below never
            // needs this, since there's no CONNECT/TLS involved on that path).
            await using SslStream sslStream = new(
                new DuplexPipeStream(context.Transport.Input, context.Transport.Output));
            await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            }, context.ConnectionClosed);

            IDuplexPipe originalTransport = context.Transport;
            context.Transport = new DuplexPipe(PipeReader.Create(sslStream), PipeWriter.Create(sslStream));
            try
            {
                await next(context);
            }
            finally
            {
                context.Transport = originalTransport;
            }
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

file sealed class DuplexPipe(PipeReader input, PipeWriter output) : IDuplexPipe
{
    public PipeReader Input { get; } = input;
    public PipeWriter Output { get; } = output;
}

// Bridges a Kestrel IDuplexPipe (raw connection bytes) to the Stream shape SslStream
// requires, so the tunneled connection's TLS handshake can be terminated manually.
file sealed class DuplexPipeStream(PipeReader input, PipeWriter output) : Stream
{
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            ReadResult result = await input.ReadAsync(cancellationToken);
            ReadOnlySequence<byte> sequence = result.Buffer;

            if (!sequence.IsEmpty)
            {
                int toCopy = (int)Math.Min(buffer.Length, sequence.Length);
                sequence.Slice(0, toCopy).CopyTo(buffer.Span);
                input.AdvanceTo(sequence.GetPosition(toCopy));
                return toCopy;
            }

            input.AdvanceTo(sequence.Start, sequence.End);

            if (result.IsCompleted)
                return 0;
        }
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await output.WriteAsync(buffer, cancellationToken);
    }

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public override void Flush() { }

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}