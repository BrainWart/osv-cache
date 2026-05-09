using System.Buffers;
using System.IO.Pipelines;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace API;

public class ConnectTunnelMiddleware(
    ConnectionDelegate next,
    HttpsConnectionAdapterOptions httpsOptions,
    ILogger<ConnectTunnelMiddleware> logger)
{
    private static readonly byte[] ConnectMethod = "CONNECT "u8.ToArray();
    private static readonly byte[] ConnectionEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();
    private static readonly byte[] BadRequest = "HTTP/1.1 400 Bad Request\r\n\r\n"u8.ToArray();

    public async Task OnConnectionAsync(ConnectionContext context)
    {
        var input = context.Transport.Input;

        var result = await input.ReadAsync();
        var buffer = result.Buffer;

        if (buffer.Length == 0)
        {
            return;
        }

        if (StartsWithConnect(buffer))
        {
            if (!TryParseConnectRequest(buffer, out var host, out var consumed))
            {
                await context.Transport.Output.WriteAsync(BadRequest);
                return;
            }

            input.AdvanceTo(buffer.GetPosition(consumed));

            logger.LogInformation("CONNECT tunnel requested for {Host}", host);

            await context.Transport.Output.WriteAsync(ConnectionEstablished);

            var sslStream = new SslStream(new DuplexPipeStream(context.Transport), leaveInnerStreamOpen: false);

            try
            {
                var sslOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificate = httpsOptions.ServerCertificate,
                    EnabledSslProtocols = httpsOptions.SslProtocols,
                    CertificateRevocationCheckMode = httpsOptions.CheckCertificateRevocation
                        ? X509RevocationMode.Online
                        : X509RevocationMode.NoCheck,
                    ClientCertificateRequired = httpsOptions.ClientCertificateMode == ClientCertificateMode.RequireCertificate,
                };

                if (httpsOptions.ServerCertificateSelector is not null)
                {
                    sslOptions.ServerCertificateSelectionCallback = (_, name) =>
                        httpsOptions.ServerCertificateSelector(context, name)!;
                }

                httpsOptions.OnAuthenticate?.Invoke(context, sslOptions);

                await sslStream.AuthenticateAsServerAsync(sslOptions);

                logger.LogDebug("TLS handshake completed for tunnel to {Host}", host);

                var sslDuplexPipe = new SslDuplexPipe(sslStream);
                var originalTransport = context.Transport;
                context.Transport = sslDuplexPipe;

                context.Features.Set<ITlsConnectionFeature>(new TlsConnectionFeature(sslStream));

                try
                {
                    await next(context);
                }
                finally
                {
                    context.Transport = originalTransport;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "TLS handshake failed for tunnel to {Host}", host);
                return;
            }
            finally
            {
                await sslStream.DisposeAsync();
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

        Span<byte> span = stackalloc byte[ConnectMethod.Length];
        buffer.Slice(0, ConnectMethod.Length).CopyTo(span);
        return span.SequenceEqual(ConnectMethod);
    }

    private static bool TryParseConnectRequest(ReadOnlySequence<byte> buffer, out string host, out int consumed)
    {
        host = string.Empty;
        consumed = 0;

        var reader = new SequenceReader<byte>(buffer);

        if (!reader.TryReadTo(out ReadOnlySpan<byte> requestLine, (byte)'\n'))
        {
            return false;
        }

        // Skip headers until we hit empty line
        while (reader.TryReadTo(out ReadOnlySpan<byte> _, (byte)'\n'))
        {
            if (reader.Remaining >= 1)
            {
                var nextByte = buffer.Slice(reader.Position).FirstSpan[0];
                if (nextByte == '\r' || nextByte == '\n')
                {
                    reader.TryReadTo(out ReadOnlySpan<byte> _, (byte)'\n');
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
        var line = Encoding.ASCII.GetString(requestLine).TrimEnd('\r', '\n');
        var parts = line.Split(' ');

        if (parts.Length < 2)
        {
            return false;
        }

        host = parts[1];
        return true;
    }
}

internal sealed class TlsConnectionFeature(SslStream sslStream) : ITlsConnectionFeature
{
    public X509Certificate2? ClientCertificate
    {
        get => sslStream.RemoteCertificate as X509Certificate2;
        set => throw new NotSupportedException();
    }

    public Task<X509Certificate2?> GetClientCertificateAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult(ClientCertificate);
    }
}

internal sealed class DuplexPipeStream(IDuplexPipe pipe) : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() { }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return ReadAsync(buffer, offset, count).GetAwaiter().GetResult();
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        var result = await pipe.Input.ReadAsync(cancellationToken);
        var bufferSequence = result.Buffer;

        if (bufferSequence.IsEmpty && result.IsCompleted)
        {
            return 0;
        }

        var bytesToCopy = (int)Math.Min(count, bufferSequence.Length);
        bufferSequence.Slice(0, bytesToCopy).CopyTo(buffer.AsSpan(offset, bytesToCopy));
        pipe.Input.AdvanceTo(bufferSequence.GetPosition(bytesToCopy));

        return bytesToCopy;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var result = await pipe.Input.ReadAsync(cancellationToken);
        var bufferSequence = result.Buffer;

        if (bufferSequence.IsEmpty && result.IsCompleted)
        {
            return 0;
        }

        var bytesToCopy = (int)Math.Min(buffer.Length, bufferSequence.Length);
        bufferSequence.Slice(0, bytesToCopy).CopyTo(buffer.Span[..bytesToCopy]);
        pipe.Input.AdvanceTo(bufferSequence.GetPosition(bytesToCopy));

        return bytesToCopy;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        WriteAsync(buffer, offset, count).GetAwaiter().GetResult();
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await pipe.Output.WriteAsync(buffer.AsMemory(offset, count), cancellationToken);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await pipe.Output.WriteAsync(buffer, cancellationToken);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}

internal sealed class SslDuplexPipe : IDuplexPipe
{
    public SslDuplexPipe(SslStream sslStream)
    {
        var inputPipe = new Pipe();
        var outputPipe = new Pipe();

        Input = inputPipe.Reader;
        Output = outputPipe.Writer;

        _ = ReadFromSslStreamAsync(sslStream, inputPipe.Writer);
        _ = WriteToSslStreamAsync(sslStream, outputPipe.Reader);
    }

    public PipeReader Input { get; }
    public PipeWriter Output { get; }

    private static async Task ReadFromSslStreamAsync(SslStream sslStream, PipeWriter writer)
    {
        try
        {
            while (true)
            {
                var memory = writer.GetMemory(4096);
                var bytesRead = await sslStream.ReadAsync(memory);

                if (bytesRead == 0)
                {
                    break;
                }

                writer.Advance(bytesRead);
                var result = await writer.FlushAsync();

                if (result.IsCompleted)
                {
                    break;
                }
            }
        }
        catch
        {
            // Connection closed
        }
        finally
        {
            await writer.CompleteAsync();
        }
    }

    private static async Task WriteToSslStreamAsync(SslStream sslStream, PipeReader reader)
    {
        try
        {
            while (true)
            {
                var result = await reader.ReadAsync();
                var buffer = result.Buffer;

                foreach (var segment in buffer)
                {
                    await sslStream.WriteAsync(segment);
                }

                reader.AdvanceTo(buffer.End);

                if (result.IsCompleted)
                {
                    break;
                }
            }
        }
        catch
        {
            // Connection closed
        }
        finally
        {
            await reader.CompleteAsync();
        }
    }
}
