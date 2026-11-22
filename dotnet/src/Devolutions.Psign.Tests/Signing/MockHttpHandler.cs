using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>A request captured by <see cref="MockHttpHandler"/>.</summary>
internal sealed record CapturedRequest(HttpMethod Method, Uri Uri, Dictionary<string, string> Headers, byte[] Body)
{
    public string BodyText => Encoding.UTF8.GetString(Body);
}

/// <summary>
/// In-memory <see cref="HttpMessageHandler"/> replacing the Rust <c>mockito</c> server: routes match method + URL regex
/// (and optional header / body predicates), every request is recorded, and each route counts its hits.
/// </summary>
internal sealed class MockHttpHandler : HttpMessageHandler
{
    private readonly List<Route> _routes = [];

    public List<CapturedRequest> Requests { get; } = [];

    public Route Map(string method, string urlRegex)
    {
        var route = new Route(new HttpMethod(method), new Regex(urlRegex));
        _routes.Add(route);
        return route;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in request.Headers)
        {
            headers[h.Key] = string.Join(", ", h.Value);
        }

        if (request.Content is not null)
        {
            foreach (var h in request.Content.Headers)
            {
                headers[h.Key] = string.Join(", ", h.Value);
            }
        }

        var captured = new CapturedRequest(request.Method, request.RequestUri!, headers, body);
        Requests.Add(captured);
        foreach (var route in _routes)
        {
            if (route.Matches(captured))
            {
                route.Hits++;
                return route.CreateResponse();
            }
        }

        return new HttpResponseMessage(HttpStatusCode.NotImplemented) { Content = new StringContent("no mock route for " + request.Method + " " + request.RequestUri) };
    }

    internal sealed class Route
    {
        private readonly HttpMethod _method;
        private readonly Regex _url;
        private readonly List<Func<CapturedRequest, bool>> _predicates = [];
        private HttpStatusCode _status = HttpStatusCode.OK;
        private byte[] _body = [];
        private readonly List<(string Name, string Value)> _headers = [];

        public Route(HttpMethod method, Regex url)
        {
            _method = method;
            _url = url;
        }

        public int Hits { get; set; }

        public Route MatchHeader(string name, string value)
        {
            _predicates.Add(r => r.Headers.TryGetValue(name, out var v) && v == value);
            return this;
        }

        public Route MatchBody(Func<string, bool> predicate)
        {
            _predicates.Add(r => predicate(r.BodyText));
            return this;
        }

        public Route Respond(int status, string body = "", params (string Name, string Value)[] headers) =>
            Respond(status, Encoding.UTF8.GetBytes(body), headers);

        public Route Respond(int status, byte[] body, params (string Name, string Value)[] headers)
        {
            _status = (HttpStatusCode)status;
            _body = body;
            _headers.AddRange(headers);
            return this;
        }

        internal bool Matches(CapturedRequest r) =>
            r.Method == _method && _url.IsMatch(r.Uri.AbsoluteUri) && _predicates.All(p => p(r));

        internal HttpResponseMessage CreateResponse()
        {
            var response = new HttpResponseMessage(_status) { Content = new ByteArrayContent(_body) };
            foreach (var (name, value) in _headers)
            {
                if (!response.Headers.TryAddWithoutValidation(name, value))
                {
                    response.Content.Headers.TryAddWithoutValidation(name, value);
                }
            }

            return response;
        }
    }
}
